package com.perfumepedia.perfumepedia.domain.request.entity;

import com.perfumepedia.perfumepedia.domain.perfume.entity.Perfume;
import com.perfumepedia.perfumepedia.domain.perfume.entity.RequestPerfume;
import com.perfumepedia.perfumepedia.domain.perfumeNote.entity.PerfumeNote;
import com.perfumepedia.perfumepedia.domain.perfumeNote.entity.RequestPerfumeNote;
import com.perfumepedia.perfumepedia.global.entity.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Request extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "REQUEST_ID")
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(name = "REQUEST_TYPE", nullable = false)
    private RequestType requestType;

    @Enumerated(EnumType.STRING)
    @Column(name = "REQUEST_STATUS", nullable = false)
    private RequestStatus requestStatus;

    @Column(name = "USER_ID", nullable = false)
    private Long userId; // 유저 객체로 변경 가능성 있음

    // 요청한 향수에 대한 정보
    @ManyToOne(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @JoinColumn(name = "REQUEST_PERFUME_ID", nullable = true)
    private RequestPerfume requestPerfume;

    // 수정, 삭제 요청시 이전 향수에 대한 정보
    @ManyToOne(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    @JoinColumn(name = "PERFUME_ID", nullable = true)
    private Perfume perfume;

    @Builder
    public Request(Long id, RequestType requestType, RequestStatus requestStatus, Long userId,
                   RequestPerfume requestPerfume, Perfume perfume) {
        this.id = id;
        this.requestType = requestType;
        this.requestStatus = requestStatus;
        this.userId = userId;
        this.requestPerfume = requestPerfume;
        this.perfume = perfume;
    }

    public void updateRequestStatus(RequestStatus newStatus) {
        this.requestStatus = newStatus;
    }

    // perfume과 requestPerfume을 null로 설정하
    public void clearPerfumeAndRequestPerfume() {
        this.perfume = null;
        this.requestPerfume = null;
    }
}
