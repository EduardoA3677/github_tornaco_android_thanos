.class public final Llyiahf/vczjk/rq4;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:I

.field public final OooO0O0:[Llyiahf/vczjk/pq4;

.field public final OooO0OO:Llyiahf/vczjk/n62;

.field public final OooO0Oo:Ljava/lang/Object;

.field public final OooO0o:I

.field public final OooO0o0:Z

.field public final OooO0oO:I

.field public final OooO0oo:I


# direct methods
.method public constructor <init>(I[Llyiahf/vczjk/pq4;Llyiahf/vczjk/n62;Ljava/util/List;ZI)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Llyiahf/vczjk/rq4;->OooO00o:I

    iput-object p2, p0, Llyiahf/vczjk/rq4;->OooO0O0:[Llyiahf/vczjk/pq4;

    iput-object p3, p0, Llyiahf/vczjk/rq4;->OooO0OO:Llyiahf/vczjk/n62;

    iput-object p4, p0, Llyiahf/vczjk/rq4;->OooO0Oo:Ljava/lang/Object;

    iput-boolean p5, p0, Llyiahf/vczjk/rq4;->OooO0o0:Z

    iput p6, p0, Llyiahf/vczjk/rq4;->OooO0o:I

    array-length p1, p2

    const/4 p3, 0x0

    move p4, p3

    move p5, p4

    :goto_0
    if-ge p4, p1, :cond_0

    aget-object p6, p2, p4

    iget p6, p6, Llyiahf/vczjk/pq4;->OooOOOo:I

    invoke-static {p5, p6}, Ljava/lang/Math;->max(II)I

    move-result p5

    add-int/lit8 p4, p4, 0x1

    goto :goto_0

    :cond_0
    iput p5, p0, Llyiahf/vczjk/rq4;->OooO0oO:I

    iget p1, p0, Llyiahf/vczjk/rq4;->OooO0o:I

    add-int/2addr p5, p1

    if-gez p5, :cond_1

    goto :goto_1

    :cond_1
    move p3, p5

    :goto_1
    iput p3, p0, Llyiahf/vczjk/rq4;->OooO0oo:I

    return-void
.end method


# virtual methods
.method public final OooO00o(III)[Llyiahf/vczjk/pq4;
    .locals 13

    iget-object v0, p0, Llyiahf/vczjk/rq4;->OooO0O0:[Llyiahf/vczjk/pq4;

    array-length v1, v0

    const/4 v2, 0x0

    move v3, v2

    move v4, v3

    :goto_0
    if-ge v2, v1, :cond_2

    aget-object v5, v0, v2

    add-int/lit8 v12, v3, 0x1

    iget-object v6, p0, Llyiahf/vczjk/rq4;->OooO0Oo:Ljava/lang/Object;

    invoke-interface {v6, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/bk3;

    iget-wide v6, v3, Llyiahf/vczjk/bk3;->OooO00o:J

    long-to-int v3, v6

    iget-object v6, p0, Llyiahf/vczjk/rq4;->OooO0OO:Llyiahf/vczjk/n62;

    iget-object v6, v6, Llyiahf/vczjk/n62;->OooOOOO:Ljava/lang/Object;

    check-cast v6, [I

    aget v7, v6, v4

    iget v6, p0, Llyiahf/vczjk/rq4;->OooO00o:I

    iget-boolean v8, p0, Llyiahf/vczjk/rq4;->OooO0o0:Z

    if-eqz v8, :cond_0

    move v10, v6

    goto :goto_1

    :cond_0
    move v10, v4

    :goto_1
    if-eqz v8, :cond_1

    move v11, v4

    move v6, p1

    move v8, p2

    move/from16 v9, p3

    goto :goto_2

    :cond_1
    move v11, v6

    move v8, p2

    move/from16 v9, p3

    move v6, p1

    :goto_2
    invoke-virtual/range {v5 .. v11}, Llyiahf/vczjk/pq4;->OooOOO0(IIIIII)V

    add-int/2addr v4, v3

    add-int/lit8 v2, v2, 0x1

    move v3, v12

    goto :goto_0

    :cond_2
    return-object v0
.end method
