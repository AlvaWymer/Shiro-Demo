package cn.mldn.shiro.service.impl;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;

import cn.mldn.shiro.service.IMemberService;
import cn.mldn.shiro.vo.Member;

public class MemberServiceImpl implements IMemberService {
	private static int count = 1 ;
	private static final String DRIVER = "org.gjt.mm.mysql.Driver";
	private static final String URL = "jdbc:mysql://localhost:3306/shirodb";
	private static final String USER = "root";
	private static final String PASSWORD = "123456";
	private Connection conn;
	public MemberServiceImpl() {	// 只要创建子类对象就表示创建连接
		System.out.println("****************** 数据库操作第（" + count++ + "）次");
		try {
			Class.forName(DRIVER);
			this.conn = DriverManager.getConnection(URL, USER, PASSWORD);
		} catch (Exception e) {
		}
	}
	@Override
	public Set<String> listRolesByMember(String mid) throws Exception {
		Set<String> allRoles = new HashSet<String>() ;
		String sql = "SELECT rid FROM member_role WHERE mid=?" ;
		PreparedStatement pstmt = this.conn.prepareStatement(sql) ;
		pstmt.setString(1, mid);
		ResultSet rs = pstmt.executeQuery() ;
		while (rs.next()) {
			allRoles.add(rs.getString(1)) ;
		}
		return allRoles ;
	}
	@Override
	public Set<String> listActionsByMember(String mid) throws Exception {
		Set<String> allActions = new HashSet<String>() ;
		String sql = "SELECT actid FROM action WHERE rid IN ("
				+ "	SELECT rid FROM member_role WHERE mid=?)" ;
		PreparedStatement pstmt = this.conn.prepareStatement(sql) ;
		pstmt.setString(1, mid);
		ResultSet rs = pstmt.executeQuery() ;
		while (rs.next()) {
			allActions.add(rs.getString(1)) ;
		}
		this.close() ;
		return allActions;
	}
	@Override
	public Member get(String id) throws Exception {
		String sql = "SELECT mid,name,password,locked FROM member WHERE mid=?"  ;
		PreparedStatement pstmt = this.conn.prepareStatement(sql) ;
		pstmt.setString(1, id);
		ResultSet rs = pstmt.executeQuery() ;
		if (rs.next()) {
			Member vo = new Member() ;
			vo.setMid(rs.getString(1));
			vo.setName(rs.getString(2));
			vo.setPassword(rs.getString(3));
			vo.setLocked(rs.getInt(4));
			return vo ;
		}
		this.close() ;
		return null;
	}
	public void close() {
		try {
			this.conn.close();
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}
}
