# Báo cáo chi tiết kịch bản Authentication trong hệ thống SDN

## 1. Mục tiêu của kịch bản

Kịch bản Authentication trong dự án này được thiết kế để điều khiển quyền truy cập ở tầng mạng dựa trên trạng thái xác thực của địa chỉ IP. Hệ thống kết hợp giữa bộ điều khiển SDN viết bằng Ryu và một cổng xác thực web viết bằng Flask. Mục tiêu chính là:

1. Chặn ngay các IP nằm trong blacklist.
2. Cho phép các IP nằm trong whitelist tĩnh đi qua mà không cần xác thực lại.
3. Cấp quyền tạm thời cho IP đã xác thực qua portal, với thời gian sống của phiên có giới hạn.
4. Đọc dữ liệu cấu hình từ file JSON theo thời gian thực để thay đổi chính sách mà không cần khởi động lại toàn bộ luồng xử lý.

## 2. Thành phần của hệ thống

### 2.1. Bộ điều khiển SDN: `auth_controller.py`

File này định nghĩa lớp `AuthController`, kế thừa từ `RyuApp`. Nhiệm vụ của nó là nhận sự kiện gói tin từ switch, kiểm tra IP nguồn và quyết định cho phép hoặc loại bỏ lưu lượng.

Chức năng chính:

- Theo dõi ánh xạ MAC sang cổng để forward lớp 2.
- Đọc whitelist, blacklist và session từ các file JSON nằm cùng thư mục với file controller.
- Chặn IP trong blacklist bằng flow rule drop.
- Cho phép IP trong whitelist hoặc IP có session còn hiệu lực.
- Tạo flow tạm thời cho các kết nối hợp lệ để giảm số lần gửi PacketIn về controller.

### 2.2. Cổng xác thực web: `portal_app.py`

Đây là ứng dụng Flask đóng vai trò cổng đăng nhập/ xác thực IP. Người dùng truy cập portal, nhập IP cần xác thực, hệ thống sẽ ghi IP đó vào `sessions.json` cùng với thời điểm hết hạn.

Chức năng chính:

- Hiển thị giao diện xác thực đơn giản.
- Tự nhận diện IP từ `X-Forwarded-For` hoặc `remote_addr`.
- Xác thực định dạng IP bằng thư viện `ipaddress`.
- Lưu session vào file JSON bằng thao tác ghi an toàn thông qua file tạm.
- Cung cấp API `/sessions` để xem trạng thái các phiên còn hiệu lực.

### 2.3. Tệp dữ liệu chính

- `whitelist.json`: danh sách IP được phép mặc định.
- `blacklist.json`: danh sách IP bị từ chối tuyệt đối.
- `sessions.json`: danh sách IP đã xác thực tạm thời kèm thời điểm hết hạn.

Trong trạng thái hiện tại của workspace:

- `whitelist.json` chứa `10.0.0.3`.
- `blacklist.json` chứa `10.0.0.2`.
- `sessions.json` đang có session cho `10.0.0.1`.

## 3. Kiến trúc luồng xử lý

Luồng xử lý có thể mô tả theo thứ tự sau:

1. Switch nhận gói tin và gửi PacketIn về controller khi chưa có flow phù hợp.
2. `AuthController` nhận gói tin, trích xuất Ethernet frame và nếu có IPv4 thì kiểm tra IP nguồn.
3. Controller đọc lại whitelist, blacklist và session từ file trên đĩa để đảm bảo dữ liệu mới nhất.
4. Nếu IP nằm trong blacklist, controller cài flow drop với độ ưu tiên cao và dừng xử lý.
5. Nếu IP nằm trong whitelist, gói tin được phép đi tiếp.
6. Nếu IP không nằm trong whitelist nhưng còn session hợp lệ, gói tin vẫn được cho phép.
7. Nếu IP không hợp lệ theo chính sách, controller chỉ log và drop gói tin mà không tạo flow permit.
8. Với các gói tin được phép, controller forward theo MAC learning switch và có thể lưu flow để giảm tải về sau.

## 4. Phân tích chi tiết logic trong controller

### 4.1. Đường dẫn file và tính ổn định khi chạy

Controller xác định `base_dir` từ vị trí của chính file `auth_controller.py`. Nhờ đó, mọi file JSON được đọc bằng đường dẫn tuyệt đối tương đối với file nguồn, tránh lỗi khi khởi chạy `ryu-manager` từ thư mục khác.

Đây là điểm quan trọng vì nếu dùng đường dẫn tương đối theo current working directory, controller có thể không tìm thấy `whitelist.json`, `blacklist.json` hoặc `sessions.json`.

### 4.2. Cơ chế đọc dữ liệu động

Mỗi lần xử lý PacketIn, controller gọi lại hàm đọc file để lấy dữ liệu mới nhất. Điều này có nghĩa là:

- Sửa `whitelist.json` hoặc `blacklist.json` có hiệu lực gần như ngay lập tức.
- Session trong `sessions.json` được đánh giá động theo thời gian hiện tại.

Ưu điểm là dễ quản trị và thay đổi chính sách nhanh. Nhược điểm là mỗi PacketIn đều phải đọc file, nên với lưu lượng lớn sẽ có chi phí I/O cao hơn so với cache trong bộ nhớ.

### 4.3. Thứ tự kiểm tra quyền truy cập

Thứ tự kiểm tra hiện tại là:

1. Blacklist.
2. Whitelist.
3. Session còn hiệu lực.
4. Nếu không thuộc ba nhóm trên thì drop.

Thứ tự này hợp lý vì blacklist có độ ưu tiên cao nhất. Một IP dù có session hay từng được xác thực cũng sẽ bị chặn nếu nằm trong blacklist.

### 4.4. Chặn blacklist

Khi IP nguồn nằm trong blacklist, controller tạo flow match với `eth_type=0x0800` và `ipv4_src=<ip>` rồi thêm action rỗng. Trong OpenFlow, action rỗng tương đương drop.

Ý nghĩa:

- Chặn ngay gói hiện tại.
- Cài flow để các gói sau từ cùng IP tiếp tục bị drop ở switch, không cần quay về controller.

### 4.5. Cho phép whitelist và session

Nếu IP nằm trong whitelist, controller log là đã được xác thực theo danh sách tĩnh.

Nếu IP không có trong whitelist nhưng còn session hợp lệ, controller cũng cho phép đi qua. Session hợp lệ được xác định bằng cách so thời gian hiện tại với `expires_at` đã lưu trong `sessions.json`.

### 4.6. Hành vi với IP chưa xác thực

Nếu một IP không thuộc whitelist, blacklist hoặc session còn hiệu lực, controller chỉ log trạng thái chưa xác thực rồi drop gói tin. Điểm cần lưu ý là ở nhánh này controller không tạo flow permit, nên IP phải đi qua portal trước khi truy cập được tài nguyên mạng.

### 4.7. Học địa chỉ MAC và forward L2

Sau khi qua lớp kiểm tra xác thực, controller thực hiện cơ chế MAC learning giống switch lớp 2:

- Lưu `src_mac -> in_port` theo từng `dpid`.
- Nếu đã biết `dst_mac`, gửi ra đúng cổng đã học.
- Nếu chưa biết, flood ra toàn mạng trong phạm vi switch.

Như vậy, phần xác thực được đặt phía trước, còn phần forwarding vẫn tận dụng logic quen thuộc của switch học MAC.

### 4.8. Flow tạm thời cho session hợp lệ

Khi gói tin được forward trên cổng cụ thể, controller có thể cài flow với `hard_timeout=60` nếu gói IPv4 đến từ session còn hiệu lực. Điều này giúp kết nối hợp lệ duy trì trong một khoảng thời gian ngắn mà không cần hỏi controller liên tục.

Tác dụng thực tế:

- Giảm số lượng PacketIn.
- Tăng hiệu năng cho các kết nối hợp lệ.
- Vẫn giữ được tính kiểm soát vì flow có thời hạn.

## 5. Phân tích chi tiết `portal_app.py`

### 5.1. Quản lý session

Portal dùng `SESSION_TTL_SECONDS = 60`, tức mỗi lần xác thực thành công sẽ cấp quyền trong 60 giây.

Quy trình lưu session:

1. Đọc session hiện tại từ `sessions.json`.
2. Lọc bỏ các session đã hết hạn.
3. Thêm IP mới với thời gian hết hạn mới.
4. Ghi toàn bộ cấu trúc `{"sessions": ...}` ra file.

### 5.2. Cách nhận diện IP người dùng

Hàm `detect_client_ip()` ưu tiên lấy `X-Forwarded-For` từ header HTTP. Nếu header không có, nó fallback sang `request.remote_addr`.

Điều này phù hợp khi portal đi sau reverse proxy hoặc Nginx, vì IP thật của người dùng có thể được chuyển tiếp qua header.

### 5.3. Xác thực IP đầu vào

Trước khi lưu session, portal kiểm tra IP bằng `ipaddress.ip_address()`. Nếu giá trị không hợp lệ, portal trả về lỗi và không ghi vào file.

Điểm này giúp tránh lưu dữ liệu rác hoặc chuỗi không phải IP thật vào session store.

### 5.4. Giao diện người dùng

Giao diện được dựng trực tiếp bằng `render_template_string`, không cần file HTML riêng. Trang hiển thị:

- IP phát hiện của client.
- Ô nhập IP cần xác thực.
- Nút xác thực.
- Thời gian hiệu lực của phiên.

Đây là một thiết kế tối giản, đủ để phục vụ lab hoặc demo kỹ thuật.

### 5.5. API kiểm tra session

Endpoint `/sessions` trả về JSON gồm danh sách session hiện tại và tổng số phiên. Endpoint này hữu ích cho việc kiểm tra trạng thái hệ thống trong quá trình thử nghiệm.

## 6. Cấu hình topology và hạ tầng liên quan

### 6.1. `Topo command/controller.txt`

File này ghi lệnh cài đặt môi trường Python và Ryu:

- Cập nhật package system.
- Cài `python3-pip`, `python3-dev`.
- Cài `ryu`.
- Cài các dependency như `greenlet`, `eventlet`, `dnspython`, `webob`, `tinyrpc`.

Điều này cho thấy controller dự kiến chạy trên hệ điều hành Linux với môi trường OpenFlow/Ryu chuẩn.

### 6.2. `Topo command/gateway.txt`

File này mô tả phần gateway/bridge:

- Cài `openvswitch-switch`.
- Cài `nginx`.
- Tạo bridge `br-int`.
- Gắn VXLAN interface `vx-s0`.
- Gán IP `10.0.0.254/24` cho bridge.

Suy ra hệ thống có một tầng trung gian làm gateway hoặc integration bridge để nối các máy web và mạng SDN.

### 6.3. `Topo command/bin.txt`

File này chứa cấu hình Nginx reverse proxy cho ba host ảo:

- `web1.35.186.145.237.nip.io` -> `10.0.0.1`
- `web2.35.186.145.237.nip.io` -> `10.0.0.2`
- `web3.35.186.145.237.nip.io` -> `10.0.0.3`

Nginx truyền tiếp header `X-Forwarded-For`, nên portal có thể nhận IP thực của client tốt hơn. Đây là điểm kết nối trực tiếp với `detect_client_ip()` trong portal.

## 7. Kịch bản hoạt động mẫu

### 7.1. IP nằm trong blacklist

Ví dụ `10.0.0.2` hiện nằm trong `blacklist.json`.

Khi gói tin từ IP này đi vào switch:

1. Controller nhận PacketIn.
2. Thấy IP nằm trong blacklist.
3. Log trạng thái bị chặn.
4. Cài flow drop ưu tiên cao.
5. Từ chối lưu lượng ngay lập tức.

### 7.2. IP nằm trong whitelist

Ví dụ `10.0.0.3` nằm trong `whitelist.json`.

Khi gói tin từ IP này xuất hiện:

1. Controller kiểm tra blacklist và không thấy trùng.
2. Kiểm tra whitelist và thấy hợp lệ.
3. Cho phép forwarding theo MAC learning bình thường.
4. Có thể cài flow để tối ưu xử lý các gói sau.

### 7.3. IP chưa có trong danh sách nhưng đã xác thực qua portal

Ví dụ `10.0.0.1` đang có session trong `sessions.json`.

Khi gói tin từ IP này đi qua:

1. Controller không thấy trong blacklist.
2. Không thấy trong whitelist.
3. Thấy session vẫn còn hiệu lực.
4. Cho phép lưu lượng đi qua.
5. Nếu phù hợp, cài flow có `hard_timeout` để session chỉ tồn tại trong thời gian giới hạn.

### 7.4. IP chưa xác thực

Nếu IP không thuộc ba nhóm trên, controller chỉ drop gói tin. Trạng thái này buộc người dùng phải truy cập portal để đăng ký session trước khi được phép vào mạng.

## 8. Đánh giá thiết kế

### 8.1. Ưu điểm

- Phân tách rõ giữa phần điều khiển lưu lượng và phần cấp quyền xác thực.
- Dễ thay đổi chính sách bằng file JSON mà không cần sửa sâu code.
- Có cả whitelist tĩnh và session động nên linh hoạt cho nhiều chế độ vận hành.
- Có cơ chế chặn blacklist ở mức flow để tiết kiệm tài nguyên controller.

### 8.2. Hạn chế

- Controller đọc file JSON ở mỗi lần PacketIn nên có thể phát sinh overhead I/O khi tải cao.
- Session được lưu theo IP, nên nếu nhiều user cùng NAT ra một địa chỉ IP thì phân biệt danh tính sẽ kém chính xác.
- Portal đang dùng giao diện rất tối giản, phù hợp demo hơn là production.
- `portal_app.py` hiện cho phép người dùng tự nhập IP để xác thực, vì vậy trong môi trường thật cần cơ chế ràng buộc danh tính hoặc xác thực bổ sung.

### 8.3. Rủi ro cần chú ý

- Nếu thời gian đồng bộ giữa các máy không tốt, session theo `time.time()` có thể gây lệch thực tế sử dụng.
- Nếu file JSON bị sửa tay sai định dạng, hệ thống sẽ fallback về dữ liệu rỗng và có thể gây chặn nhầm.
- Nên bảo vệ file `sessions.json` khỏi ghi đồng thời khi triển khai nhiều tiến trình portal.

## 9. Kết luận

Kịch bản Authentication của dự án là một mô hình SDN nhẹ, dễ hiểu và phù hợp cho mục tiêu demo/lab. Luồng xác thực được triển khai theo ba lớp chính: blacklist để chặn tuyệt đối, whitelist để cho phép cố định, và session portal để cấp quyền tạm thời. Kiến trúc này giúp kiểm soát truy cập ở tầng mạng mà vẫn giữ được tính linh hoạt nhờ dữ liệu JSON động.

Nếu cần phát triển tiếp, các hướng nâng cấp hợp lý là:

1. Thêm cache trong controller để giảm chi phí đọc file.
2. Thêm cơ chế xác thực người dùng thực thay vì chỉ xác thực IP.
3. Tách giao diện portal thành template riêng để dễ bảo trì.
4. Bổ sung logging và kiểm thử cho các trạng thái blacklist/whitelist/session.
