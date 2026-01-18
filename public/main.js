
/* أحرف الخلفية */

const letters = ["E","L","C","T","R","O","N","V"];
const bg = document.getElementById("bg");
for (let i = 0; i < 30; i++) {
    let s = document.createElement("span");
    s.className = "letter";
    s.innerText = letters[Math.floor(Math.random()*letters.length)];
    s.style.left = Math.random()*100 + "vw";
    s.style.animationDuration = (7 + Math.random()*6) + "s";
    bg.appendChild(s);
}

/* وظيفة الانتقال */
function go(page) {
    window.location.href = page;
}

/* روابط مع تسجيل الدخول */
function goSecure(realLink) {
    // التحقق من حالة تسجيل الدخول من السيرفر
    fetch("/auth/status", { credentials: "include" })
    .then(res => res.json())
    .then(data => {
        if (!data.loggedIn) {
            localStorage.setItem("redirectAfterLogin", realLink);
            window.location.href = "login.html";
            return;
        }

        if (realLink.startsWith("http")) {
            window.open(realLink, "_blank");
        } else {
            window.location.href = realLink;
        }
    })
    .catch(err => {
        console.error("خطأ في التحقق:", err);
        // في حالة الخطأ، افترض أنه غير مسجل
        localStorage.setItem("redirectAfterLogin", realLink);
        window.location.href = "login.html";
    });
}

/* ذيل النيون */
const trailContainer = document.getElementById("trail-container");
const navHeight = 80;

window.addEventListener("mousemove", (e) => {
    if (e.clientY < navHeight + 10) return;

    let dot = document.createElement("div");
    dot.className = "trail";
    dot.style.left = e.clientX + "px";
    dot.style.top = e.clientY + "px";
    trailContainer.appendChild(dot);

    setTimeout(() => { dot.remove(); }, 320);
});

/* عرض البروفايل بعد تسجيل الدخول */
window.addEventListener("DOMContentLoaded", () => {
    checkAuthStatus();
    initScrollAnimations();
});

/* أنيميشن العناصر عند النزول */
function initScrollAnimations() {
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('animate');
            }
        });
    }, observerOptions);

    // مراقبة العناصر التي تحتوي على كلاسات الأنيميشن
    document.querySelectorAll('.fade-in-left, .fade-in-right, .fade-in-up').forEach(el => {
        observer.observe(el);
    });
}

async function checkAuthStatus() {
    try {
        const response = await fetch("/auth/status", {
            credentials: "include"
        });
        const data = await response.json();

        const loginBtn = document.getElementById("login-btn");
        const profile = document.getElementById("profile");

        if (data.loggedIn) {
            // المستخدم مسجل دخول
            loginBtn.style.display = "none";
            profile.style.display = "flex";
            profile.innerText = data.email.charAt(0).toUpperCase();
            profile.title = data.email;
            profile.classList.add("profile-appear");

            // إضافة قائمة منسدلة للبروفايل
            profile.onclick = showProfileMenu;
        } else {
            // المستخدم غير مسجل دخول
            loginBtn.style.display = "block";
            profile.style.display = "none";
            document.getElementById("profileSection").style.display = "none";
        }
    } catch (error) {
        console.error("خطأ في التحقق من حالة الدخول:", error);
        // في حالة الخطأ، إظهار زر تسجيل الدخول
        document.getElementById("login-btn").style.display = "block";
        document.getElementById("profile").style.display = "none";
        document.getElementById("profileSection").style.display = "none";
    }
}

function showProfileMenu() {
    // إنشاء قائمة منسدلة للبروفايل
    let menu = document.getElementById("profile-menu");
    if (menu) {
        menu.remove();
        return;
    }

    menu = document.createElement("div");
    menu.id = "profile-menu";
    menu.innerHTML = `
        <div class="profile-menu-item" onclick="go('profile.html')">البروفايل</div>
        <div class="profile-menu-item" onclick="logout()">تسجيل الخروج</div>
    `;
    menu.style.cssText = `
        position: absolute;
        top: 70px;
        right: 20px;
        background: rgba(15,15,20,0.95);
        border: 1px solid rgba(255,255,255,0.1);
        border-radius: 8px;
        padding: 8px 0;
        min-width: 150px;
        backdrop-filter: blur(10px);
        z-index: 1000;
        box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    `;

    const menuItems = menu.querySelectorAll(".profile-menu-item");
    menuItems.forEach(item => {
        item.style.cssText = `
            padding: 12px 16px;
            cursor: pointer;
            color: #fff;
            font-size: 14px;
            transition: 0.2s;
        `;
        item.onmouseover = () => item.style.background = "rgba(255,255,255,0.1)";
        item.onmouseout = () => item.style.background = "transparent";
    });

    document.body.appendChild(menu);

    // إغلاق القائمة عند النقر خارجها
    setTimeout(() => {
        document.addEventListener("click", function closeMenu(e) {
            if (!menu.contains(e.target) && e.target !== document.getElementById("profile")) {
                menu.remove();
                document.removeEventListener("click", closeMenu);
            }
        });
    }, 10);
}



async function logout() {
    try {
        const response = await fetch("/logout", {
            method: "POST",
            credentials: "include"
        });
        const data = await response.json();

        if (data.ok) {
            // إعادة تحميل الصفحة لتحديث الواجهة
            window.location.reload();
        } else {
            alert("خطأ في تسجيل الخروج");
        }
    } catch (error) {
        console.error("خطأ:", error);
        alert("حدث خطأ في تسجيل الخروج");
    }
}


function toggleMenu() {
    const nav = document.getElementById("nav-links");
    const burger = document.querySelector(".hamburger");

    nav.classList.toggle("show");
    burger.classList.toggle("active");
}
document.querySelectorAll("#nav-links li").forEach(li => {
    li.addEventListener("click", () => {
        document.getElementById("nav-links").classList.remove("show");
        document.querySelector(".hamburger").classList.remove("active");
    });
});





const lamp = document.querySelector(".lamp-head");
const cord = document.querySelector(".lamp-cord");
const root = document.documentElement;

let pulling = false;
let startY = 0;

/* تحميل الثيم المحفوظ */
async function loadTheme() {
    try {
        const authRes = await fetch("/auth/status", { credentials: "include" });
        const auth = await authRes.json();
        if (auth.loggedIn) {
            const themeRes = await fetch("/api/user-theme", { credentials: "include" });
            const themeData = await themeRes.json();
            root.setAttribute("data-theme", themeData.theme);
        } else {
            const savedTheme = localStorage.getItem("theme");
            if (savedTheme) {
                root.setAttribute("data-theme", savedTheme);
            }
        }
    } catch (e) {
        const savedTheme = localStorage.getItem("theme");
        if (savedTheme) {
            root.setAttribute("data-theme", savedTheme);
        }
    }
}
loadTheme();

lamp.addEventListener("mousedown", e => {
  pulling = true;
  startY = e.clientY;
  lamp.style.cursor = "grabbing";
});

window.addEventListener("mousemove", e => {
  if (!pulling) return;

  let distance = e.clientY - startY;
  if (distance < 0) distance = 0;
  if (distance > 120) distance = 120;

  lamp.style.transform = `translateY(${distance}px)`;
  cord.style.height = 130 + distance + "px";
});

window.addEventListener("mouseup", () => {
  if (!pulling) return;
  pulling = false;

  lamp.style.transform = "translateY(0)";
  cord.style.height = "130px";
  lamp.style.cursor = "grab";

  /* تبديل الثيم */
  const current = root.getAttribute("data-theme");
  const next = current === "light" ? "dark" : "light";
  root.setAttribute("data-theme", next);
  
  // حفظ الثيم
  fetch("/auth/status", { credentials: "include" })
    .then(res => res.json())
    .then(auth => {
        if (auth.loggedIn) {
            fetch("/api/user-theme", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                credentials: "include",
                body: JSON.stringify({ theme: next })
            });
        } else {
            localStorage.setItem("theme", next);
        }
    })
    .catch(() => {
        localStorage.setItem("theme", next);
    });
});

document.addEventListener("DOMContentLoaded", () => {
    const hamburger = document.querySelector(".hamburger");

    if (!hamburger) return;

    // إذا العرض أكبر من 992px نعتبره لابتوب / ديسكتوب
    if (window.innerWidth >= 992) {
        hamburger.remove();
    }
});
