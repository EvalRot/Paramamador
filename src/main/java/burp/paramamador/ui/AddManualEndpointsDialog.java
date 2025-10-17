package burp.paramamador.ui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * Dialog allowing users to add endpoints manually.
 * Fields: list of endpoints (one per line), source JS, referer/origin.
 */
public class AddManualEndpointsDialog extends JDialog {
    public static record ManualData(List<String> endpoints, String sourceJs, String referer) {}

    private final JTextArea endpointsArea = new JTextArea();
    private final JTextField sourceJsField = new JTextField();
    private final JTextField refererField = new JTextField();

    public AddManualEndpointsDialog(Window owner, Consumer<ManualData> onSave) {
        super(owner, "Add Endpoints Manually", ModalityType.APPLICATION_MODAL);
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setLayout(new BorderLayout(8,8));

        // Left: multi-line endpoints list
        endpointsArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        endpointsArea.setLineWrap(false);
        JScrollPane endpointsScroll = new JScrollPane(endpointsArea);
        endpointsScroll.setBorder(BorderFactory.createTitledBorder("URL endpoints (one per line)"));

        // Right: fields for source and referer
        JPanel right = new JPanel();
        right.setLayout(new BoxLayout(right, BoxLayout.Y_AXIS));
        JPanel srcPanel = new JPanel(new BorderLayout(4,4));
        srcPanel.add(new JLabel("Source JS"), BorderLayout.NORTH);
        srcPanel.add(sourceJsField, BorderLayout.CENTER);
        JPanel refPanel = new JPanel(new BorderLayout(4,4));
        refPanel.add(new JLabel("Referer/Origin"), BorderLayout.NORTH);
        refPanel.add(refererField, BorderLayout.CENTER);
        right.add(srcPanel);
        right.add(Box.createVerticalStrut(8));
        right.add(refPanel);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, endpointsScroll, right);
        split.setResizeWeight(0.7);
        add(split, BorderLayout.CENTER);

        JButton save = new JButton("Save");
        JButton cancel = new JButton("Cancel");
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttons.add(save);
        buttons.add(cancel);
        add(buttons, BorderLayout.SOUTH);

        cancel.addActionListener((ActionEvent e) -> dispose());
        save.addActionListener((ActionEvent e) -> {
            try {
                List<String> eps = parseEndpoints(endpointsArea.getText());
                if (eps.isEmpty()) {
                    JOptionPane.showMessageDialog(this, "Please provide at least one endpoint.", "Paramamador", JOptionPane.WARNING_MESSAGE);
                    return;
                }
                ManualData data = new ManualData(eps, textOrNull(sourceJsField.getText()), textOrNull(refererField.getText()));
                if (onSave != null) onSave.accept(data);
                dispose();
            } catch (Throwable ex) {
                JOptionPane.showMessageDialog(this, "Failed: " + ex.getMessage(), "Paramamador", JOptionPane.ERROR_MESSAGE);
            }
        });

        setSize(760, 460);
        setLocationRelativeTo(owner);
    }

    private static String textOrNull(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private static List<String> parseEndpoints(String text) {
        List<String> out = new ArrayList<>();
        if (text == null) return out;
        String[] lines = text.split("\r?\n");
        for (String line : lines) {
            if (line == null) continue;
            String t = line.trim();
            if (t.isEmpty()) continue;
            out.add(t);
        }
        return out;
    }
}

