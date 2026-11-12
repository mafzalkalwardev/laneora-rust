const invoke = (command, args) => {
  if (window.__TAURI__ && window.__TAURI__.core) {
    return window.__TAURI__.core.invoke(command, args);
  }
  return Promise.reject(new Error("This window runs inside Laneora Rust on Windows."));
};

const names = {
  dat: "DAT Search",
  dat_dual: "Dual DAT Search",
  dat_3: "3 DAT Search",
  dat_4: "4 DAT Search",
};

document.getElementById("login").addEventListener("submit", async (event) => {
  event.preventDefault();
  const error = document.getElementById("error");
  error.textContent = "";
  try {
    const signed = await invoke("login", {
      server: document.getElementById("server").value,
      username: document.getElementById("username").value,
      password: document.getElementById("password").value,
    });
    document.getElementById("login").hidden = true;
    document.getElementById("modules").hidden = false;
    document.getElementById("status").textContent = signed.subscription_end
      ? `Signed in. Plan ends ${signed.subscription_end}.`
      : "Signed in.";
    const buttons = document.getElementById("buttons");
    buttons.innerHTML = "";
    for (const service of signed.services) {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = names[service] || service;
      button.addEventListener("click", async () => {
        try {
          await invoke("open_search", { service });
        } catch (err) {
          error.textContent = String(err);
        }
      });
      buttons.appendChild(button);
    }
  } catch (err) {
    error.textContent = String(err);
  }
});
