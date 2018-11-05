package test;

import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JButton;
import javax.swing.JTextField;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.JTextPane;
import javax.swing.JTextArea;
import javax.swing.JEditorPane;
import client.Client;
import protobuf.sSegment;
import protobuf.SegmentPB.Segment;
import rsa.Rsa;

import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.SwingConstants;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

public class clform {

	private Client client;
	private JFrame frame;
	private JTextField textReceiverId;
	private JTextField textMessage;
	private JTextField textClientId;
	private Thread readMessage;
	private JLabel lblReceiver;
	private JTextArea textArea;
	
	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					clform window = new clform();
					window.frame.setVisible(true);
					window.client.connect();
					
					window.textClientId.setText(window.client.identifier);
					
					window.readMessage.start();
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public clform() {
		client = new Client("35.220.137.70", 5003);
		initialize();
		readMessage = new Thread(new clientRead(client, textArea));
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frame = new JFrame();
		frame.setBounds(100, 100, 608, 368);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		
		JButton btnSend = new JButton("Send");
		btnSend.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				String receiver = textReceiverId.getText();
				String message = textMessage.getText();
				client.sending = true;
				try {
					textArea.append(client.identifier + "\n< " + message + "\n");
					client.sendMessage(receiver, message);
					textMessage.setText("");
				} catch (Exception e) {
					e.printStackTrace();
				}
				client.sending = false;
			}
		});
		
		textReceiverId = new JTextField();
		textReceiverId.setColumns(10);
		
		textMessage = new JTextField();
		textMessage.setColumns(10);
		
		JLabel lblId = new JLabel("ID");
		
		textClientId = new JTextField();
		textClientId.setColumns(10);
		
		lblReceiver = new JLabel("Receiver");
		
		textArea = new JTextArea();
		
		JButton btnPublicKey = new JButton("Public Key");
		btnPublicKey.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				JOptionPane.showMessageDialog(null, "PublicKey: \n" + Rsa.getString(client.pubkey) + "\nVerification Key: \n" + Rsa.getString(client.verkey));
			}
		});
		
		GroupLayout groupLayout = new GroupLayout(frame.getContentPane());
		groupLayout.setHorizontalGroup(
			groupLayout.createParallelGroup(Alignment.TRAILING)
				.addGroup(groupLayout.createSequentialGroup()
					.addContainerGap()
					.addGroup(groupLayout.createParallelGroup(Alignment.TRAILING)
						.addComponent(textArea, Alignment.LEADING, GroupLayout.DEFAULT_SIZE, 491, Short.MAX_VALUE)
						.addComponent(textMessage, GroupLayout.DEFAULT_SIZE, 491, Short.MAX_VALUE)
						.addGroup(groupLayout.createSequentialGroup()
							.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
								.addGroup(groupLayout.createSequentialGroup()
									.addComponent(lblId, GroupLayout.DEFAULT_SIZE, 24, Short.MAX_VALUE)
									.addGap(30))
								.addGroup(groupLayout.createSequentialGroup()
									.addComponent(lblReceiver)
									.addPreferredGap(ComponentPlacement.RELATED)))
							.addGroup(groupLayout.createParallelGroup(Alignment.TRAILING)
								.addComponent(textClientId, GroupLayout.DEFAULT_SIZE, 437, Short.MAX_VALUE)
								.addComponent(textReceiverId, GroupLayout.DEFAULT_SIZE, 437, Short.MAX_VALUE))))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addGroup(groupLayout.createParallelGroup(Alignment.TRAILING)
						.addGroup(groupLayout.createSequentialGroup()
							.addComponent(btnPublicKey)
							.addGap(12))
						.addGroup(groupLayout.createSequentialGroup()
							.addComponent(btnSend)
							.addContainerGap())))
		);
		groupLayout.setVerticalGroup(
			groupLayout.createParallelGroup(Alignment.TRAILING)
				.addGroup(groupLayout.createSequentialGroup()
					.addContainerGap()
					.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
						.addComponent(lblId)
						.addComponent(textClientId, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
						.addComponent(btnPublicKey))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
						.addComponent(textReceiverId, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
						.addComponent(lblReceiver))
					.addGap(18)
					.addComponent(textArea, GroupLayout.PREFERRED_SIZE, 177, GroupLayout.PREFERRED_SIZE)
					.addPreferredGap(ComponentPlacement.RELATED, 26, Short.MAX_VALUE)
					.addGroup(groupLayout.createParallelGroup(Alignment.BASELINE)
						.addComponent(textMessage, GroupLayout.PREFERRED_SIZE, 37, GroupLayout.PREFERRED_SIZE)
						.addComponent(btnSend))
					.addContainerGap())
		);
		frame.getContentPane().setLayout(groupLayout);
	}
}

class clientRead implements Runnable
{
	
	public Client client;
	public JTextArea textConsole;
	public boolean c;
	
	public clientRead(Client client, JTextArea textConsole)
	{
		this.client = client;
		this.textConsole = textConsole;
	}

	@Override
	public void run() 
	{
		while (true)
		{
			try
			{
				if ((client.sending == false) && (client.dis.available() > 0))
				{
					Segment received = client.receiveSegment();
					if (sSegment.isRequestSendMessage(received))
					{
						String identifier = received.getSender();
						int length = Integer.parseInt(received.getLength());
						
						String mess = client.receiveMessage(identifier, length);
						textConsole.append(identifier + "\n> " + mess + "\n");
					}
				}
				c = client.sending;
			}
			catch (Exception e)
			{
				e.printStackTrace();
			}
		}
	}
	
}

