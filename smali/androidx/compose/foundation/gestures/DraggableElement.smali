.class public final Landroidx/compose/foundation/gestures/DraggableElement;
.super Llyiahf/vczjk/tl5;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Llyiahf/vczjk/tl5;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0000\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00020\u0001\u00a8\u0006\u0003"
    }
    d2 = {
        "Landroidx/compose/foundation/gestures/DraggableElement;",
        "Llyiahf/vczjk/tl5;",
        "Llyiahf/vczjk/zf2;",
        "foundation_release"
    }
    k = 0x1
    mv = {
        0x1,
        0x9,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field public final OooOOO:Llyiahf/vczjk/nf6;

.field public final OooOOO0:Llyiahf/vczjk/ag2;

.field public final OooOOOO:Z

.field public final OooOOOo:Llyiahf/vczjk/rr5;

.field public final OooOOo:Llyiahf/vczjk/rf2;

.field public final OooOOo0:Z

.field public final OooOOoo:Llyiahf/vczjk/bf3;

.field public final OooOo00:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ag2;Llyiahf/vczjk/nf6;ZLlyiahf/vczjk/rr5;ZLlyiahf/vczjk/rf2;Llyiahf/vczjk/bf3;Z)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOO0:Llyiahf/vczjk/ag2;

    iput-object p2, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOO:Llyiahf/vczjk/nf6;

    iput-boolean p3, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOOO:Z

    iput-object p4, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOOo:Llyiahf/vczjk/rr5;

    iput-boolean p5, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOo0:Z

    iput-object p6, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOo:Llyiahf/vczjk/rf2;

    iput-object p7, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOoo:Llyiahf/vczjk/bf3;

    iput-boolean p8, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOo00:Z

    return-void
.end method


# virtual methods
.method public final OooOO0()Llyiahf/vczjk/jl5;
    .locals 5

    new-instance v0, Llyiahf/vczjk/zf2;

    sget-object v1, Llyiahf/vczjk/ke0;->Oooo0O0:Llyiahf/vczjk/ke0;

    iget-boolean v2, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOOO:Z

    iget-object v3, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOOo:Llyiahf/vczjk/rr5;

    iget-object v4, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOO:Llyiahf/vczjk/nf6;

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/kf2;-><init>(Llyiahf/vczjk/oe3;ZLlyiahf/vczjk/rr5;Llyiahf/vczjk/nf6;)V

    iget-object v1, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOO0:Llyiahf/vczjk/ag2;

    iput-object v1, v0, Llyiahf/vczjk/zf2;->Oooo0OO:Llyiahf/vczjk/ag2;

    iput-object v4, v0, Llyiahf/vczjk/zf2;->Oooo0o0:Llyiahf/vczjk/nf6;

    iget-boolean v1, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOo0:Z

    iput-boolean v1, v0, Llyiahf/vczjk/zf2;->Oooo0o:Z

    iget-object v1, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOo:Llyiahf/vczjk/rf2;

    iput-object v1, v0, Llyiahf/vczjk/zf2;->Oooo0oO:Llyiahf/vczjk/rf2;

    iget-object v1, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOoo:Llyiahf/vczjk/bf3;

    iput-object v1, v0, Llyiahf/vczjk/zf2;->Oooo0oo:Llyiahf/vczjk/bf3;

    iget-boolean v1, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOo00:Z

    iput-boolean v1, v0, Llyiahf/vczjk/zf2;->Oooo:Z

    return-object v0
.end method

.method public final OooOO0O(Llyiahf/vczjk/jl5;)V
    .locals 6

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/zf2;

    sget-object v1, Llyiahf/vczjk/ke0;->Oooo0O0:Llyiahf/vczjk/ke0;

    iget-object p1, v0, Llyiahf/vczjk/zf2;->Oooo0OO:Llyiahf/vczjk/ag2;

    iget-object v2, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOO0:Llyiahf/vczjk/ag2;

    invoke-static {p1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    const/4 v3, 0x1

    if-nez p1, :cond_0

    iput-object v2, v0, Llyiahf/vczjk/zf2;->Oooo0OO:Llyiahf/vczjk/ag2;

    move p1, v3

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    iget-object v2, v0, Llyiahf/vczjk/zf2;->Oooo0o0:Llyiahf/vczjk/nf6;

    iget-object v4, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOO:Llyiahf/vczjk/nf6;

    if-eq v2, v4, :cond_1

    iput-object v4, v0, Llyiahf/vczjk/zf2;->Oooo0o0:Llyiahf/vczjk/nf6;

    move p1, v3

    :cond_1
    iget-boolean v2, v0, Llyiahf/vczjk/zf2;->Oooo:Z

    iget-boolean v5, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOo00:Z

    if-eq v2, v5, :cond_2

    iput-boolean v5, v0, Llyiahf/vczjk/zf2;->Oooo:Z

    move v5, v3

    goto :goto_1

    :cond_2
    move v5, p1

    :goto_1
    iget-object p1, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOo:Llyiahf/vczjk/rf2;

    iput-object p1, v0, Llyiahf/vczjk/zf2;->Oooo0oO:Llyiahf/vczjk/rf2;

    iget-object p1, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOoo:Llyiahf/vczjk/bf3;

    iput-object p1, v0, Llyiahf/vczjk/zf2;->Oooo0oo:Llyiahf/vczjk/bf3;

    iget-boolean p1, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOo0:Z

    iput-boolean p1, v0, Llyiahf/vczjk/zf2;->Oooo0o:Z

    iget-boolean v2, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOOO:Z

    iget-object v3, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOOo:Llyiahf/vczjk/rr5;

    invoke-virtual/range {v0 .. v5}, Llyiahf/vczjk/kf2;->o0000O0O(Llyiahf/vczjk/oe3;ZLlyiahf/vczjk/rr5;Llyiahf/vczjk/nf6;Z)V

    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    if-ne p0, p1, :cond_0

    goto :goto_1

    :cond_0
    if-nez p1, :cond_1

    goto :goto_0

    :cond_1
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    const-class v1, Landroidx/compose/foundation/gestures/DraggableElement;

    if-eq v1, v0, :cond_2

    goto :goto_0

    :cond_2
    check-cast p1, Landroidx/compose/foundation/gestures/DraggableElement;

    iget-object v0, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOO0:Llyiahf/vczjk/ag2;

    iget-object v1, p1, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOO0:Llyiahf/vczjk/ag2;

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_3

    goto :goto_0

    :cond_3
    iget-object v0, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOO:Llyiahf/vczjk/nf6;

    iget-object v1, p1, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOO:Llyiahf/vczjk/nf6;

    if-eq v0, v1, :cond_4

    goto :goto_0

    :cond_4
    iget-boolean v0, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOOO:Z

    iget-boolean v1, p1, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOOO:Z

    if-eq v0, v1, :cond_5

    goto :goto_0

    :cond_5
    iget-object v0, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOOo:Llyiahf/vczjk/rr5;

    iget-object v1, p1, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOOo:Llyiahf/vczjk/rr5;

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_6

    goto :goto_0

    :cond_6
    iget-boolean v0, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOo0:Z

    iget-boolean v1, p1, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOo0:Z

    if-eq v0, v1, :cond_7

    goto :goto_0

    :cond_7
    iget-object v0, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOo:Llyiahf/vczjk/rf2;

    iget-object v1, p1, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOo:Llyiahf/vczjk/rf2;

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_8

    goto :goto_0

    :cond_8
    iget-object v0, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOoo:Llyiahf/vczjk/bf3;

    iget-object v1, p1, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOoo:Llyiahf/vczjk/bf3;

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_9

    goto :goto_0

    :cond_9
    iget-boolean v0, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOo00:Z

    iget-boolean p1, p1, Landroidx/compose/foundation/gestures/DraggableElement;->OooOo00:Z

    if-eq v0, p1, :cond_a

    :goto_0
    const/4 p1, 0x0

    return p1

    :cond_a
    :goto_1
    const/4 p1, 0x1

    return p1
.end method

.method public final hashCode()I
    .locals 3

    iget-object v0, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOO0:Llyiahf/vczjk/ag2;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    const/16 v1, 0x1f

    mul-int/2addr v0, v1

    iget-object v2, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOO:Llyiahf/vczjk/nf6;

    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    move-result v2

    add-int/2addr v2, v0

    mul-int/2addr v2, v1

    iget-boolean v0, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOOO:Z

    invoke-static {v2, v1, v0}, Llyiahf/vczjk/q99;->OooO0O0(IIZ)I

    move-result v0

    iget-object v2, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOOo:Llyiahf/vczjk/rr5;

    if-eqz v2, :cond_0

    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    move-result v2

    goto :goto_0

    :cond_0
    const/4 v2, 0x0

    :goto_0
    add-int/2addr v0, v2

    mul-int/2addr v0, v1

    iget-boolean v2, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOo0:Z

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/q99;->OooO0O0(IIZ)I

    move-result v0

    iget-object v2, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOo:Llyiahf/vczjk/rf2;

    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    move-result v2

    add-int/2addr v2, v0

    mul-int/2addr v2, v1

    iget-object v0, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOOoo:Llyiahf/vczjk/bf3;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    add-int/2addr v0, v2

    mul-int/2addr v0, v1

    iget-boolean v1, p0, Landroidx/compose/foundation/gestures/DraggableElement;->OooOo00:Z

    invoke-static {v1}, Ljava/lang/Boolean;->hashCode(Z)I

    move-result v1

    add-int/2addr v1, v0

    return v1
.end method
