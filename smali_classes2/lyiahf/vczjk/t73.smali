.class public final Llyiahf/vczjk/t73;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Lcom/bumptech/glide/request/RequestListener;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/o000OO;

.field public final OooOOO0:Llyiahf/vczjk/s77;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/s77;Llyiahf/vczjk/o000OO;)V
    .locals 1

    const-string v0, "producerScope"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/t73;->OooOOO0:Llyiahf/vczjk/s77;

    iput-object p2, p0, Llyiahf/vczjk/t73;->OooOOO:Llyiahf/vczjk/o000OO;

    return-void
.end method


# virtual methods
.method public final onLoadFailed(Lcom/bumptech/glide/load/engine/GlideException;Ljava/lang/Object;Lcom/bumptech/glide/request/target/Target;Z)Z
    .locals 0

    const-string p2, "target"

    invoke-static {p3, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p2, p0, Llyiahf/vczjk/t73;->OooOOO:Llyiahf/vczjk/o000OO;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/o000OO;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    const/4 p1, 0x0

    return p1
.end method

.method public final onResourceReady(Ljava/lang/Object;Ljava/lang/Object;Lcom/bumptech/glide/request/target/Target;Lcom/bumptech/glide/load/DataSource;Z)Z
    .locals 0

    const-string p3, "resource"

    invoke-static {p1, p3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p3, "model"

    invoke-static {p2, p3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p2, "dataSource"

    invoke-static {p4, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p2, Llyiahf/vczjk/cv3;

    sget-object p3, Llyiahf/vczjk/u73;->OooO00o:[I

    invoke-virtual {p4}, Ljava/lang/Enum;->ordinal()I

    move-result p4

    aget p3, p3, p4

    const/4 p4, 0x1

    if-eq p3, p4, :cond_4

    const/4 p5, 0x2

    if-eq p3, p5, :cond_3

    const/4 p5, 0x3

    if-eq p3, p5, :cond_2

    const/4 p5, 0x4

    if-eq p3, p5, :cond_1

    const/4 p5, 0x5

    if-ne p3, p5, :cond_0

    sget-object p3, Llyiahf/vczjk/yx1;->OooOOO0:Llyiahf/vczjk/yx1;

    goto :goto_0

    :cond_0
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_1
    sget-object p3, Llyiahf/vczjk/yx1;->OooOOO:Llyiahf/vczjk/yx1;

    goto :goto_0

    :cond_2
    sget-object p3, Llyiahf/vczjk/yx1;->OooOOO:Llyiahf/vczjk/yx1;

    goto :goto_0

    :cond_3
    sget-object p3, Llyiahf/vczjk/yx1;->OooOOOO:Llyiahf/vczjk/yx1;

    goto :goto_0

    :cond_4
    sget-object p3, Llyiahf/vczjk/yx1;->OooOOO:Llyiahf/vczjk/yx1;

    :goto_0
    invoke-direct {p2, p1, p3}, Llyiahf/vczjk/cv3;-><init>(Ljava/lang/Object;Llyiahf/vczjk/yx1;)V

    iget-object p1, p0, Llyiahf/vczjk/t73;->OooOOO0:Llyiahf/vczjk/s77;

    invoke-static {p1, p2}, Llyiahf/vczjk/t51;->OooooOO(Llyiahf/vczjk/if8;Llyiahf/vczjk/dv3;)V

    check-cast p1, Llyiahf/vczjk/r77;

    const/4 p2, 0x0

    invoke-virtual {p1, p2}, Llyiahf/vczjk/r77;->OooO0o(Ljava/lang/Throwable;)Z

    return p4
.end method
