package com.myblog9.service;

import com.myblog9.payload.CommentDto;

import java.util.List;

public interface CommentService {

    public CommentDto createComment(long postId, CommentDto commentDto);

    public void deleteCommentById(long postId, long commentId);

    List<CommentDto> getCommentsByPostId(long postId);



    CommentDto updateComment(long commentId, CommentDto commentDto);
}
