package com.myblog9.service.impl;

import com.myblog9.entity.Comment;
import com.myblog9.entity.Post;
import com.myblog9.exception.ResourceNotFound;
import com.myblog9.payload.CommentDto;
import com.myblog9.repository.CommentRepository;
import com.myblog9.repository.PostRepository;
import com.myblog9.service.CommentService;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class CommentServiceImpl implements CommentService {

    private CommentRepository commentRepo;

    private PostRepository postRepo;
    private Post post;
    private ModelMapper modelMapper;

    public CommentServiceImpl(CommentRepository commentRepo, PostRepository postRepo,ModelMapper modelMapper) {
        this.commentRepo = commentRepo;
        this.postRepo = postRepo;
        this.modelMapper = modelMapper;
    }


//    Create Or Save Comment

    @Override
    public CommentDto createComment(long postId, CommentDto commentDto) {     //This "CommentDto" come from "CommentController" , the createComment takes postId and commentDto.
        Post post = postRepo.findById(postId).orElseThrow(                                    //Then createComment will search for "Post" Exist.
                () -> new ResourceNotFound("Post Not Found with id:" + postId)
        );


        Comment comment = mapToEntity(commentDto);                                          //If yes then it will save the comment
    comment.setPost(post);                                                               //If it doesnot exist it will not save the comment.
    Comment c = commentRepo.save(comment);

    return mapToDto(c);                                                                 //Once the comment is saved it will return back the Dto.
}


//     Delete Comment
    @Override
    public void deleteCommentById(long postId, long commentId) {
        Post post = postRepo.findById(postId).orElseThrow(
                () -> new ResourceNotFound("Post Not Found with id:" + postId)
        );
        commentRepo.deleteById(commentId);
    }

    @Override
    public List<CommentDto> getCommentsByPostId(long postId) {
        List<Comment> comments = commentRepo.findByPostId(postId);
        List<CommentDto> dtos = comments.stream().map(comment -> mapToDto(comment)).collect(Collectors.toList());
        return dtos;
    }

    @Override
    public CommentDto updateComment(long commentId, CommentDto commentDto) {
        Comment com = commentRepo.findById(commentId).get();
        Post post = postRepo.findById(com.getPost().getId()).get();
        Comment comment = mapToEntity(commentDto);
        comment.setPost(post);
        comment.setId(commentId);

        Comment savedComment = commentRepo.save(comment);
        CommentDto dto = mapToDto(savedComment);
        return dto;
    }


    CommentDto mapToDto(Comment comment){
        CommentDto dto = modelMapper.map(comment,CommentDto.class);
//        CommentDto dto = new CommentDto();
//            dto.setName(comment.getName());
//            dto.setEmail(comment.getEmail());
//            dto.setBody(comment.getBody());
            return dto;
    }

       Comment mapToEntity(CommentDto dto){
        Comment comment = modelMapper.map(dto, Comment.class);
//        Comment comment = new Comment();
//        comment.setName(dto.getName());
//        comment.setEmail(dto.getEmail());
//        comment.setBody(dto.getBody());
           return comment;
       }
}
