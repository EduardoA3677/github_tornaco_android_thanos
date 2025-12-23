.class public final Llyiahf/vczjk/dg;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $isLeft:Z

.field final synthetic $isStartHandle:Z

.field final synthetic $offsetProvider:Llyiahf/vczjk/v86;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/v86;ZZ)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/dg;->$offsetProvider:Llyiahf/vczjk/v86;

    iput-boolean p2, p0, Llyiahf/vczjk/dg;->$isStartHandle:Z

    iput-boolean p3, p0, Llyiahf/vczjk/dg;->$isLeft:Z

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    check-cast p1, Llyiahf/vczjk/af8;

    iget-object v0, p0, Llyiahf/vczjk/dg;->$offsetProvider:Llyiahf/vczjk/v86;

    invoke-interface {v0}, Llyiahf/vczjk/v86;->OooO00o()J

    move-result-wide v3

    sget-object v0, Llyiahf/vczjk/zd8;->OooO0OO:Llyiahf/vczjk/ze8;

    new-instance v1, Llyiahf/vczjk/yd8;

    iget-boolean v2, p0, Llyiahf/vczjk/dg;->$isStartHandle:Z

    if-eqz v2, :cond_0

    sget-object v2, Llyiahf/vczjk/tl3;->OooOOO:Llyiahf/vczjk/tl3;

    goto :goto_0

    :cond_0
    sget-object v2, Llyiahf/vczjk/tl3;->OooOOOO:Llyiahf/vczjk/tl3;

    :goto_0
    iget-boolean v5, p0, Llyiahf/vczjk/dg;->$isLeft:Z

    if-eqz v5, :cond_1

    sget-object v5, Llyiahf/vczjk/xd8;->OooOOO0:Llyiahf/vczjk/xd8;

    goto :goto_1

    :cond_1
    sget-object v5, Llyiahf/vczjk/xd8;->OooOOOO:Llyiahf/vczjk/xd8;

    :goto_1
    const-wide v6, 0x7fffffff7fffffffL

    and-long/2addr v6, v3

    const-wide v8, 0x7fc000007fc00000L    # 2.247117487993712E307

    cmp-long v6, v6, v8

    if-eqz v6, :cond_2

    const/4 v6, 0x1

    goto :goto_2

    :cond_2
    const/4 v6, 0x0

    :goto_2
    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/yd8;-><init>(Llyiahf/vczjk/tl3;JLlyiahf/vczjk/xd8;Z)V

    check-cast p1, Llyiahf/vczjk/je8;

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
