# Monthly Target Tracker (Netlify + Blobs)

- public/index.html — หน้าเว็บ (ภาพรวมร้าน + รายบุคคล)
- netlify/functions/data.mjs — API เก็บข้อมูล/รูปด้วย Netlify Blobs (/api/data, /api/photo)
- ตั้ง Environment variable ชื่อ ADMIN_KEY แล้ว deploy ใหม่

ลิงก์
- ภาพรวมร้าน: https://<ชื่อเว็บ>.netlify.app/#store
- หน้าของพนักงานแต่ละคน: https://<ชื่อเว็บ>.netlify.app/#s<รหัสพนักงาน>  เช่น #s7700
- ผู้ดูแล: https://<ชื่อเว็บ>.netlify.app/#admin
