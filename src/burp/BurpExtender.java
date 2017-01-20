package burp;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.regex.*;
import javax.swing.*;

public class BurpExtender implements IBurpExtender, IContextMenuFactory
{
	private IExtensionHelpers helpers;
	private final static String[] helpText = {
		"<html><body>By clicking on <b>Apply</b> below, the selected items will have</body></html>",
		"their comments set to the first group of the above regular",
		"expression applied to the selected data source."
	};
	private final static String NAME = "Commentator";

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
	{
		helpers = callbacks.getHelpers();
		callbacks.setExtensionName(NAME);
		callbacks.registerContextMenuFactory(this);
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
		return Collections.singletonList(i);
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

	private void showDialog(Frame owner, final IHttpRequestResponse[] messages) {
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

		cs.gridx = 0; cs.gridwidth = 2;
		for (String line : helpText) {
			cs.gridy++;
			panel.add(new JLabel(line), cs);
		}

		JButton btnApply = new JButton("Apply");
		JButton btnCancel = new JButton("Cancel");
		btnCancel.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				dlg.dispose();
			}
		});
		btnApply.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				Pattern p = handleRegexpCompilation(dlg, tfRegExp.getText(), checkBoxMapToFlags(cbFlags));
				if (p == null) return;
				RequestResponse rr = (RequestResponse)cbSource.getSelectedItem();
				boolean ow = cbOverwrite.isSelected();
				generateCommentForMessages(messages, ow, rr, p);
				dlg.dispose();
			}
		});
		JPanel pnButtons = new JPanel();
		pnButtons.add(btnApply);
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

	private static int checkBoxMapToFlags(Map<RegExpFlag, JCheckBox> cbFlags) {
		int flags = 0;
		for (Map.Entry<RegExpFlag, JCheckBox> e : cbFlags.entrySet()) {
			if (e.getValue().isSelected()) flags |= e.getKey().value;
		}
		return flags;
	}

	private static Pattern handleRegexpCompilation(Component parent, String regexp, int flags) {
		try {
			return Pattern.compile(regexp, flags);
		} catch (PatternSyntaxException pse) {
			JOptionPane.showMessageDialog(parent, pse.getMessage(),
					"Syntax error in regular expression", JOptionPane.ERROR_MESSAGE);
			return null;
		}
	}

	private void generateCommentForMessages(IHttpRequestResponse[] messages,
			boolean overwrite, RequestResponse source, Pattern regexp) {
		for (IHttpRequestResponse message : messages) {
			String comment = message.getComment();
			if (!(comment == null || comment.isEmpty() || overwrite)) continue;
			Matcher m = regexp.matcher(helpers.bytesToString(source.getSource(message)));
			if (m.find()) message.setComment(m.group(1));
		}
	}
}
