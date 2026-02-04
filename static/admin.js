const tabs = document.querySelectorAll(".tab");
tabs.forEach(tab => {
  tab.addEventListener("click", () => {
    tabs.forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));

    tab.classList.add("active");
    document.getElementById(tab.dataset.tab).classList.add("active");

    if (tab.dataset.tab === "users") {
      fetchUsers(); 
    }
  });
});

async function fetchUsers() {
  const res = await fetch("/admin/get-users");
  if (!res.ok) return;

  const users = await res.json();
  const tbody = document.querySelector(".users-table tbody");
  tbody.innerHTML = ""; 

users.forEach(user => {
  const tr = document.createElement("tr");
  tr.setAttribute("data-user-id", user.id);
  tr.innerHTML = `
    <td><input type="checkbox" class="user-checkbox" value="${user.id}"></td>
    <td class="user-cell">
      <div class="avatar">${user.name[0].toUpperCase()}</div>
      <div>
        <strong>${user.name}</strong>
        <span>${user.email}</span>
      </div>
    </td>
    <td><span class="role-badge ${user.role}">${user.role}</span></td>
    <td><span class="status-badge ${user.status.toLowerCase()}">${capitalize(user.status)}</span></td>
    <td>${user.created_at}</td>
  `;
  tbody.appendChild(tr);
});

  initUserManagement();
}

function capitalize(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

function initUserManagement() {
  const userSearch = document.getElementById("userSearch");
  const activateBtn = document.getElementById("activateBtn");
  const suspendBtn = document.getElementById("suspendBtn");
  const selectAll = document.getElementById("selectAll");

  if (!userSearch || !activateBtn || !suspendBtn || !selectAll) return;

  const checkboxes = document.querySelectorAll(".user-checkbox");

  function updateButtonVisibility() {
    const anyChecked = document.querySelectorAll(".user-checkbox:checked").length > 0;
    activateBtn.style.display = anyChecked ? "inline-block" : "none";
    suspendBtn.style.display = anyChecked ? "inline-block" : "none";
  }

  checkboxes.forEach(cb => cb.addEventListener("change", updateButtonVisibility));

  selectAll.addEventListener("change", () => {
    checkboxes.forEach(cb => cb.checked = selectAll.checked);
    updateButtonVisibility();
  });

  userSearch.addEventListener("input", () => {
    const filter = userSearch.value.toLowerCase();
    document.querySelectorAll(".users-table tbody tr").forEach(row => {
      const name = row.querySelector(".user-cell strong").innerText.toLowerCase();
      const email = row.querySelector(".user-cell span").innerText.toLowerCase();
      row.style.display = name.includes(filter) || email.includes(filter) ? "" : "none";
    });
  });

  async function updateUserStatus(newStatus) {
    const selectedIds = Array.from(
      document.querySelectorAll(".user-checkbox:checked")
    ).map(cb => cb.value);

    if (!selectedIds.length) return;

    const res = await fetch("/admin/update-user-status", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user_ids: selectedIds, status: newStatus })
    });

    if (!res.ok) return;

    const data = await res.json();

    data.updated.forEach(u => {
      const row = document.querySelector(`tr[data-user-id='${u.id}']`);
      const badge = row.querySelector(".status-badge");
      badge.innerText = capitalize(u.status);
      badge.className = `status-badge ${u.status}`;
      row.querySelector(".user-checkbox").checked = false;
    });

    selectAll.checked = false;
    updateButtonVisibility();
  }

  activateBtn.onclick = () => updateUserStatus("active");
  suspendBtn.onclick = () => updateUserStatus("suspended");
}


async function updateDashboardStats() {
  const res = await fetch("/admin/stats");
  const data = await res.json();

  document.getElementById("totalUsers").innerText = data.total_users;
  document.getElementById("activeUsers").innerText = data.active_users;
  document.getElementById("processingQueue").innerText = data.processing_queue;
  document.getElementById("totalStorage").innerText = data.total_storage_used + " MB";
}

setInterval(updateDashboardStats, 10000);
updateDashboardStats(); 

async function updateRecentActivity() {
  const res = await fetch("/admin/recent-activity");
  const data = await res.json();

  const list = document.getElementById("activityList");
  list.innerHTML = "";

  data.forEach(act => {
    const li = document.createElement("li");
    li.innerHTML = `
      <div class="activity-icon">
        <i class="fa-solid fa-bolt"></i>
      </div>
      <div class="activity-info">
        <p>${act.description}</p>
        <span>${new Date(act.timestamp).toLocaleString()}</span>
      </div>
    `;
    list.appendChild(li);
  });
}

updateRecentActivity();
setInterval(updateRecentActivity, 10000);

const COLORS = {
  completed: "#19c37d",
  processing: "#6b7cff",
  queued: "#f5a623",
  failed: "#ff5c5c",
};

let processingChart = null;


function renderProcessingChart() {
  const canvas = document.getElementById("processingChart");
  if (!canvas) return;

  fetch("/admin/analytics/processing")
    .then(res => res.json())
    .then(data => {
      const days = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"];
      const statuses = ["completed","processing","queued","failed"];
      const datasets = statuses.map(status => ({
        label: status,
        data: days.map(day => data[day]?.[status] || 0),
        backgroundColor: COLORS[status],
        borderRadius: 6
      }));

      if (processingChart) {
        processingChart.data.datasets = datasets;
        processingChart.update();
      } else {
        processingChart = new Chart(canvas, {
          type: "bar",
          data: { labels: days, datasets },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { position: "bottom" } },
            scales: {
              x: { grid: { display: false } },
              y: { beginAtZero: true }
            }
          }
        });
      }
    })
    .catch(err => console.error("Failed to fetch processing chart data:", err));
}


function renderStorage() {
  fetch("/admin/analytics/storage")
    .then(res => res.json())
    .then(data => {
      const totalMB = 20 * 1024;
      const usedMB = data.total_used || 0;
      const percent = Math.min((usedMB / totalMB) * 100, 100);
      document.getElementById("storagePercent").innerText = percent.toFixed(1) + "%";
      document.getElementById("storageFill").style.width = percent + "%";
      document.getElementById("videoSize").innerText =
        (data.by_type.video || 0).toFixed(2) + " MB";
      document.getElementById("audioSize").innerText =
        (data.by_type.audio || 0).toFixed(2) + " MB";
      document.getElementById("imageSize").innerText =
        (data.by_type.image || 0).toFixed(2) + " MB";
      document.getElementById("storageUsed").innerText =
        (usedMB).toFixed(2) + " MB / " + totalMB + " MB";
    })
    .catch(err => console.error("Failed to fetch storage data:", err));
}
renderStorage();
renderProcessingChart();
setInterval(() => {
  renderStorage();
  renderProcessingChart();
}, 30000);
