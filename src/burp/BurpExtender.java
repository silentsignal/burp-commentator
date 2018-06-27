package burp;

import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.util.*;
import java.util.regex.*;
import javax.swing.*;

public class BurpExtender implements IBurpExtender, IContextMenuFactory, IExtensionStateListener
{
	private IExtensionHelpers helpers;
	private IBurpExtenderCallbacks callbacks;
	private final static String[] helpText = {
		"<html><body>By clicking on <b>Apply</b> below, the selected items will have</body></html>",
		"their comments set to the first group of the above regular",
		"expression applied to the selected data source."
	};
	private final static String NAME = "Commentator";
	private Settings currentSettings = null;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
	{
		this.callbacks = callbacks;
		helpers = callbacks.getHelpers();
		callbacks.setExtensionName(NAME);
		callbacks.registerContextMenuFactory(this);
		callbacks.registerExtensionStateListener(this);
		currentSettings = Settings.load(callbacks);
	}

	@Override
	public void extensionUnloaded() {
		if (currentSettings != null) currentSettings.save(callbacks);
	}

	@Override
	public java.util.List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		final IHttpRequestResponse[] messages = invocation.getSelectedMessages();
		if (messages == null || messages.length == 0) return null;
		JMenuItem i = new JMenuItem("Generate comment field...");
		i.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				// src: https://coderanch.com/t/346777/java/parent-frame-JMenuItem-ActionListener
				JMenuItem menuItem = (JMenuItem)e.getSource();
				JPopupMenu popupMenu = (JPopupMenu) menuItem.getParent();
				Component invoker = popupMenu.getInvoker();
				JComponent invokerAsJComponent = (JComponent) invoker;
				Container topLevel = invokerAsJComponent.getTopLevelAncestor();
				showDialog((Frame)topLevel, messages);
			}
		});
		JMenuItem i2 = new JMenuItem("Generate comment field using last settings");
		if (currentSettings == null) {
			i2.setEnabled(false);
		} else {
			i2.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					generateCommentForMessages(messages);
				}
			});
		}
		return Arrays.asList(i, i2);
	}

	private enum RequestResponse {
		REQUEST  {byte[] getSource(IHttpRequestResponse hrr) { return hrr.getRequest(); }},
		RESPONSE {byte[] getSource(IHttpRequestResponse hrr) { return hrr.getResponse();}};

		abstract byte[] getSource(IHttpRequestResponse hrr);

		@Override
		public String toString() {
			return super.toString().toLowerCase();
		}
	}

	private enum RegExpFlag {
		CASE_INSENSITIVE, MULTILINE, DOTALL, UNICODE_CASE, CANON_EQ,
		UNIX_LINES, LITERAL, UNICODE_CHARACTER_CLASS, COMMENTS;

		public final int value;
		
		RegExpFlag() {
			int v;
			try {
				v = Pattern.class.getField(super.toString()).getInt(null);
			} catch (Exception e) {
				v = 0;
			}
			value = v;
		}

		@Override
		public String toString() {
			 return super.toString().toLowerCase().replace("_", " ");
		}
	}

	private void showDialog(final Frame owner, final IHttpRequestResponse[] messages) {
		final JDialog dlg = new JDialog(owner, NAME, true);
		JPanel panel = new JPanel(new GridBagLayout());
		GridBagConstraints cs = new GridBagConstraints();
		cs.fill = GridBagConstraints.HORIZONTAL;

		cs.gridx = 0; cs.gridy = 0; cs.gridwidth = 1;
		panel.add(new JLabel("Data source: "), cs);

		cs.gridx = 1;
		final JComboBox cbSource = new JComboBox(RequestResponse.values());
		panel.add(cbSource, cs);

		cs.gridx = 0; cs.gridy = 1;
		panel.add(new JLabel("Regular expression: "), cs);

		cs.gridx = 1;
		final JTextField tfRegExp = new JTextField();
		panel.add(tfRegExp, cs);

		cs.gridx = 0; cs.gridy = 2; cs.gridwidth = 2;
		final JCheckBox cbOverwrite = new JCheckBox("overwrite comments on items that already have one");
		panel.add(cbOverwrite, cs);

		cs.gridy = 3;
		panel.add(new JLabel("Regular expression flags: (see JDK documentation)"), cs);

		cs.gridy = 4; cs.gridwidth = 1;
		final Map<RegExpFlag, JCheckBox> cbFlags = new EnumMap<RegExpFlag, JCheckBox>(RegExpFlag.class);
		for (RegExpFlag flag : RegExpFlag.values()) {
			JCheckBox cb = new JCheckBox(flag.toString());
			panel.add(cb, cs);
			cbFlags.put(flag, cb);
			if (cs.gridx == 0) {
				cs.gridx = 1;
			} else {
				cs.gridy++;
				cs.gridx = 0;
			}
		}

		if (currentSettings != null) {
			cbSource.setSelectedItem(currentSettings.source);
			tfRegExp.setText(currentSettings.pattern.toString());
			cbOverwrite.setSelected(currentSettings.overwrite);
			int flags = currentSettings.pattern.flags();
			for (Map.Entry<RegExpFlag, JCheckBox> e : cbFlags.entrySet()) {
				e.getValue().setSelected((e.getKey().value & flags) != 0);
			}
		}

		cs.gridx = 0; cs.gridwidth = 2;
		for (String line : helpText) {
			cs.gridy++;
			panel.add(new JLabel(line), cs);
		}

		JButton btnApply = new JButton("Apply");
		JButton btnReset = new JButton("Reset");
		JButton btnCancel = new JButton("Cancel");
		btnCancel.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				dlg.dispose();
			}
		});
		btnReset.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				dlg.dispose();
				currentSettings = null;
				showDialog(owner, messages);
			}
		});
		btnApply.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				Pattern p = handleRegexpCompilation(new SwingErrorHandler(dlg),
						tfRegExp.getText(), checkBoxMapToFlags(cbFlags));
				if (p == null) return;
				RequestResponse rr = (RequestResponse)cbSource.getSelectedItem();
				boolean ow = cbOverwrite.isSelected();
				currentSettings = new Settings(p, rr, ow);
				generateCommentForMessages(messages);
				dlg.dispose();
			}
		});
		JPanel pnButtons = new JPanel();
		pnButtons.add(btnApply);
		pnButtons.add(btnReset);
		pnButtons.add(btnCancel);
		dlg.setLayout(new BorderLayout());
		dlg.add(panel, BorderLayout.CENTER);
		dlg.add(pnButtons, BorderLayout.PAGE_END);
		JRootPane rp = dlg.getRootPane();
		rp.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		rp.setDefaultButton(btnApply);
		dlg.pack();
		dlg.setResizable(false);
		dlg.setLocationRelativeTo(owner);
		dlg.setVisible(true);
	}

	public interface ErrorHandler {
		public void displayMessage(String message, String title);
	}

	private static class SwingErrorHandler implements ErrorHandler {

		private final Component parent;

		public SwingErrorHandler(Component parent) {
			this.parent = parent;
		}

		public void displayMessage(String message, String title) {
			JOptionPane.showMessageDialog(parent, message, title, JOptionPane.ERROR_MESSAGE);
		}
	}

	private static class Settings {
		public final Pattern pattern;
		public final RequestResponse source;
		public final boolean overwrite;

		private final static String EXTENSION_SETTINGS_KEY = "settings";

		public Settings(Pattern pattern, RequestResponse source, boolean overwrite) {
			this.pattern = pattern;
			this.source = source;
			this.overwrite = overwrite;
		}

		public static Settings load(IBurpExtenderCallbacks callbacks) {
			String serialized = callbacks.loadExtensionSetting(EXTENSION_SETTINGS_KEY);
			return serialized == null ? null : deserialize(
					callbacks.getHelpers().base64Decode(serialized));
		}

		private static Settings deserialize(byte[] value) {
			try (ByteArrayInputStream bais = new ByteArrayInputStream(value)) {
				try (ObjectInputStream ois = new ObjectInputStream(bais)) {
					String pattern = ois.readUTF();
					int flags = ois.readInt();
					RequestResponse source = RequestResponse.valueOf(ois.readUTF());
					boolean overwrite = ois.readBoolean();
					return new Settings(Pattern.compile(pattern, flags), source, overwrite);
				}
			} catch (Exception e) {
				e.printStackTrace();
				return null;
			}
		}

		public void save(IBurpExtenderCallbacks callbacks) {
			byte[] serialized = serialize();
			if (serialized == null) return;
			callbacks.saveExtensionSetting(EXTENSION_SETTINGS_KEY,
					callbacks.getHelpers().base64Encode(serialized));
		}

		private byte[] serialize() {
			try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
				try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
					oos.writeUTF(pattern.pattern());
					oos.writeInt(pattern.flags());
					oos.writeUTF(source.name());
					oos.writeBoolean(overwrite);
				}
				return baos.toByteArray();
			} catch (Exception e) {
				e.printStackTrace();
				return null;
			}
		}
	}

	private static int checkBoxMapToFlags(Map<RegExpFlag, JCheckBox> cbFlags) {
		int flags = 0;
		for (Map.Entry<RegExpFlag, JCheckBox> e : cbFlags.entrySet()) {
			if (e.getValue().isSelected()) flags |= e.getKey().value;
		}
		return flags;
	}

	static Pattern handleRegexpCompilation(ErrorHandler handler, String regexp, int flags) {
		if (regexp.indexOf('(') == -1 || regexp.indexOf(')') == -1) {
			handler.displayMessage("No group was found in the regular expression. " +
					"There must be at least one group that can be used as the comment.",
					"Missing group in regular expression");
			return null;
		}
		try {
			return Pattern.compile(regexp, flags);
		} catch (PatternSyntaxException pse) {
			handler.displayMessage(pse.getMessage(), "Syntax error in regular expression");
			return null;
		}
	}

	void generateCommentForMessages(IHttpRequestResponse[] messages) {
		for (IHttpRequestResponse message : messages) {
			String comment = message.getComment();
			if (!(comment == null || comment.isEmpty() || currentSettings.overwrite)) continue;
			Matcher m = currentSettings.pattern.matcher(helpers.bytesToString(
						currentSettings.source.getSource(message)));
			if (m.find()) message.setComment(m.group(1));
		}
	}
}
