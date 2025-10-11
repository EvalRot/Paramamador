package burp.paramamador.ui;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.paramamador.util.RefererTracker;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ItemEvent;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Simple popup dialog for building and sending a raw HTTP request to Repeater,
 * with an editable Host selector (pre-populated with Referer and JS hosts).
 */
public class SendToRepeaterDialog extends JDialog {
    private final JTextArea requestArea = new JTextArea();
    private final JComboBox<String> hostCombo = new JComboBox<>();

    private RefererTracker.HostOption refererOpt;
    private RefererTracker.HostOption jsOpt;
    private RefererTracker.HostOption currentOpt;

    private final Consumer<HttpRequest> sender;

    public SendToRepeaterDialog(Window owner,
                                String endpointPath,
                                RefererTracker.HostOption refererOpt,
                                RefererTracker.HostOption jsOpt,
                                Consumer<HttpRequest> sender) {
        super(owner, "Send to Repeater", ModalityType.APPLICATION_MODAL);
        this.refererOpt = refererOpt;
        this.jsOpt = jsOpt;
        this.sender = sender;
        this.currentOpt = (refererOpt != null && refererOpt.isValid()) ? refererOpt : jsOpt;

        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setLayout(new BorderLayout(8,8));

        // Left: raw request area
        requestArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        requestArea.setLineWrap(false);
        requestArea.setText(buildDefaultRequest(endpointPath, currentHost()));
        JScrollPane left = new JScrollPane(requestArea);

        // Right: host selector (editable combobox)
        hostCombo.setEditable(true);
        DefaultComboBoxModel<String> model = new DefaultComboBoxModel<>();
        if (refererOpt != null && refererOpt.isValid()) model.addElement(refererOpt.host());
        if (jsOpt != null && jsOpt.isValid()) {
            // avoid duplicate if same host
            if (model.getIndexOf(jsOpt.host()) < 0) model.addElement(jsOpt.host());
        }
        try {
            for (String h : RefererTracker.userHosts()) {
                if (model.getIndexOf(h) < 0) model.addElement(h);
            }
        } catch (Throwable ignored) {}
        hostCombo.setModel(model);
        if (model.getSize() > 0) hostCombo.setSelectedIndex(0);
        JPanel right = new JPanel(new BorderLayout(4,4));
        right.add(new JLabel("Host header"), BorderLayout.NORTH);
        right.add(hostCombo, BorderLayout.NORTH);

        // Buttons
        JButton send = new JButton("Send");
        JButton cancel = new JButton("Cancel");
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttons.add(send);
        buttons.add(cancel);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, right);
        split.setResizeWeight(0.8);
        add(split, BorderLayout.CENTER);
        add(buttons, BorderLayout.SOUTH);

        // Host change listeners -> update Host header in request area
        hostCombo.addItemListener(e -> {
            if (e.getStateChange() == ItemEvent.SELECTED) updateHostInRequest();
        });
        // Also capture text edits when user types custom value
        Component editor = hostCombo.getEditor().getEditorComponent();
        if (editor instanceof JTextField tf) {
            tf.getDocument().addDocumentListener(new DocumentListener() {
                private void upd(DocumentEvent e) { updateHostInRequest(); }
                @Override public void insertUpdate(DocumentEvent e) { upd(e); }
                @Override public void removeUpdate(DocumentEvent e) { upd(e); }
                @Override public void changedUpdate(DocumentEvent e) { upd(e); }
            });
        }

        cancel.addActionListener((ActionEvent e) -> dispose());
        send.addActionListener((ActionEvent e) -> doSend());

        setSize(900, 500);
        setLocationRelativeTo(owner);
    }

    private String currentHost() {
        if (refererOpt != null && refererOpt.isValid()) return refererOpt.host();
        if (jsOpt != null && jsOpt.isValid()) return jsOpt.host();
        return "";
    }

    private String buildDefaultRequest(String endpointPath, String host) {
        String path = endpointPath == null ? "/" : endpointPath.trim();
        if (!path.startsWith("/")) path = "/" + path;
        StringBuilder sb = new StringBuilder();
        sb.append("GET ").append(path).append(" HTTP/1.1\r\n");
        if (host != null && !host.isBlank()) sb.append("Host: ").append(host.trim()).append("\r\n");
        sb.append("\r\n");
        return sb.toString();
    }

    private void updateHostInRequest() {
        String hostTxt = Objects.toString(hostCombo.getEditor().getItem(), "").trim();
        if (hostTxt.isEmpty()) return;
        // Update current option secure hint from typed value if contains schema
        RefererTracker.HostOption base = (refererOpt != null && refererOpt.isValid()) ? refererOpt : jsOpt;
        RefererTracker.HostOption newOpt = RefererTracker.fromUserInput(hostTxt, base);
        if (newOpt != null) currentOpt = newOpt;

        String raw = requestArea.getText();
        String updated = replaceOrInsertHostHeader(raw, newOpt.host());
        if (!raw.equals(updated)) requestArea.setText(updated);
    }

    private static String replaceOrInsertHostHeader(String raw, String host) {
        if (raw == null) raw = "";
        String[] lines = raw.split("\r?\n");
        StringBuilder out = new StringBuilder(raw.length() + 32);
        boolean hostReplaced = false;
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            if (!hostReplaced && line != null && line.toLowerCase().startsWith("host:")) {
                out.append("Host: ").append(host).append("\r\n");
                hostReplaced = true;
            } else {
                out.append(line).append("\r\n");
            }
            // insert Host after request line if headers start and no Host found
            if (i == 0 && !hostReplaced && lines.length > 1) {
                out.append("Host: ").append(host).append("\r\n");
                hostReplaced = true;
            }
        }
        // ensure final blank line
        if (!out.toString().endsWith("\r\n\r\n")) out.append("\r\n");
        return out.toString();
    }

    private void doSend() {
        try {
            String hostTxt = Objects.toString(hostCombo.getEditor().getItem(), "").trim();
            if (hostTxt.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Host cannot be empty.", "Paramamador", JOptionPane.WARNING_MESSAGE);
                return;
            }
            RefererTracker.HostOption base = (refererOpt != null && refererOpt.isValid()) ? refererOpt : jsOpt;
            RefererTracker.HostOption chosen = RefererTracker.fromUserInput(hostTxt, base);
            if (chosen == null || !chosen.isValid()) {
                JOptionPane.showMessageDialog(this, "Invalid host.", "Paramamador", JOptionPane.ERROR_MESSAGE);
                return;
            }

            String reqRaw = requestArea.getText();
            // Build HttpService using scheme hint
            boolean secure = chosen.secure();
            String hostOnly = chosen.host();
            // If user put scheme in the header editor, fromUserInput already removed it to host:port
            HttpService service = HttpService.httpService(hostOnly, secure);
            HttpRequest request = HttpRequest.httpRequest(service, reqRaw);

            try { RefererTracker.addUserHost(hostOnly); } catch (Throwable ignored) {}
            sender.accept(request);
            dispose();
        } catch (Throwable t) {
            JOptionPane.showMessageDialog(this, "Failed to send: " + t.getMessage(), "Paramamador", JOptionPane.ERROR_MESSAGE);
        }
    }
}
