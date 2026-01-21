const form = document.getElementById("chat-form");
const chat = document.getElementById("chat");

function appendMessage(role, content) {
  const wrapper = document.createElement("div");
  wrapper.className = `message ${role}`;
  const roleEl = document.createElement("span");
  roleEl.className = "role";
  roleEl.textContent = role;
  const textEl = document.createElement("p");
  textEl.textContent = content;
  wrapper.appendChild(roleEl);
  wrapper.appendChild(textEl);
  chat.appendChild(wrapper);
  chat.scrollTop = chat.scrollHeight;
  return textEl;
}

async function streamChat(prompt, csrfToken) {
  const userMsg = appendMessage("user", prompt);
  const assistantEl = appendMessage("assistant", "");
  const formData = new FormData();
  formData.append("prompt", prompt);
  formData.append("csrf_token", csrfToken);

  const response = await fetch("/api/chat/stream", {
    method: "POST",
    body: formData,
    headers: {
      "Accept": "text/event-stream",
    },
  });

  if (!response.ok || !response.body) {
    assistantEl.textContent = "Fehler beim Abruf.";
    return;
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let parts = buffer.split("\n\n");
    buffer = parts.pop();
    for (const part of parts) {
      const lines = part.split("\n");
      let event = "message";
      let data = "";
      for (const line of lines) {
        if (line.startsWith("event:")) {
          event = line.replace("event:", "").trim();
        }
        if (line.startsWith("data:")) {
          data += line.replace("data:", "").trim();
        }
      }
      if (event === "message") {
        assistantEl.textContent += data.replace(/\\n/g, "\n");
      }
      if (event === "error") {
        assistantEl.textContent = "Upstream error";
      }
    }
  }
}

if (form) {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const promptInput = document.getElementById("prompt");
    const csrfToken = form.querySelector("input[name=csrf_token]").value;
    const prompt = promptInput.value.trim();
    if (!prompt) return;
    promptInput.value = "";
    await streamChat(prompt, csrfToken);
  });
}
