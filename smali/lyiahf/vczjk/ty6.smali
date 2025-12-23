.class public final Llyiahf/vczjk/ty6;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public OooO00o:Llyiahf/vczjk/xn4;

.field public OooO0O0:Llyiahf/vczjk/py6;

.field public final synthetic OooO0OO:Llyiahf/vczjk/uy6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/uy6;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ty6;->OooO0OO:Llyiahf/vczjk/uy6;

    sget-object p1, Llyiahf/vczjk/py6;->OooOOO0:Llyiahf/vczjk/py6;

    iput-object p1, p0, Llyiahf/vczjk/ty6;->OooO0O0:Llyiahf/vczjk/py6;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/ey6;)V
    .locals 10

    iget-object v0, p1, Llyiahf/vczjk/ey6;->OooO00o:Ljava/lang/Object;

    invoke-interface {v0}, Ljava/util/Collection;->size()I

    move-result v1

    const/4 v2, 0x0

    move v3, v2

    :goto_0
    const/4 v4, 0x1

    const-string v5, "layoutCoordinates not set"

    const-wide/16 v6, 0x0

    iget-object v8, p0, Llyiahf/vczjk/ty6;->OooO0OO:Llyiahf/vczjk/uy6;

    if-ge v3, v1, :cond_3

    invoke-interface {v0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/ky6;

    invoke-virtual {v9}, Llyiahf/vczjk/ky6;->OooO0O0()Z

    move-result v9

    if-eqz v9, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/ty6;->OooO0O0:Llyiahf/vczjk/py6;

    sget-object v1, Llyiahf/vczjk/py6;->OooOOO:Llyiahf/vczjk/py6;

    if-ne v0, v1, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/ty6;->OooO00o:Llyiahf/vczjk/xn4;

    if-eqz v0, :cond_0

    invoke-interface {v0, v6, v7}, Llyiahf/vczjk/xn4;->OoooOO0(J)J

    move-result-wide v0

    new-instance v2, Llyiahf/vczjk/qy6;

    invoke-direct {v2, v8}, Llyiahf/vczjk/qy6;-><init>(Llyiahf/vczjk/uy6;)V

    invoke-static {p1, v0, v1, v2, v4}, Llyiahf/vczjk/er8;->OooOo0(Llyiahf/vczjk/ey6;JLlyiahf/vczjk/oe3;Z)V

    goto :goto_1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-direct {p1, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    :goto_1
    sget-object p1, Llyiahf/vczjk/py6;->OooOOOO:Llyiahf/vczjk/py6;

    iput-object p1, p0, Llyiahf/vczjk/ty6;->OooO0O0:Llyiahf/vczjk/py6;

    return-void

    :cond_2
    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_3
    iget-object v1, p0, Llyiahf/vczjk/ty6;->OooO00o:Llyiahf/vczjk/xn4;

    if-eqz v1, :cond_7

    invoke-interface {v1, v6, v7}, Llyiahf/vczjk/xn4;->OoooOO0(J)J

    move-result-wide v5

    new-instance v1, Llyiahf/vczjk/ry6;

    invoke-direct {v1, p0, v8}, Llyiahf/vczjk/ry6;-><init>(Llyiahf/vczjk/ty6;Llyiahf/vczjk/uy6;)V

    invoke-static {p1, v5, v6, v1, v2}, Llyiahf/vczjk/er8;->OooOo0(Llyiahf/vczjk/ey6;JLlyiahf/vczjk/oe3;Z)V

    iget-object v1, p0, Llyiahf/vczjk/ty6;->OooO0O0:Llyiahf/vczjk/py6;

    sget-object v3, Llyiahf/vczjk/py6;->OooOOO:Llyiahf/vczjk/py6;

    if-ne v1, v3, :cond_6

    invoke-interface {v0}, Ljava/util/Collection;->size()I

    move-result v1

    :goto_2
    if-ge v2, v1, :cond_4

    invoke-interface {v0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/ky6;

    invoke-virtual {v3}, Llyiahf/vczjk/ky6;->OooO00o()V

    add-int/lit8 v2, v2, 0x1

    goto :goto_2

    :cond_4
    iget-object p1, p1, Llyiahf/vczjk/ey6;->OooO0O0:Llyiahf/vczjk/hl1;

    if-nez p1, :cond_5

    goto :goto_3

    :cond_5
    iget-boolean v0, v8, Llyiahf/vczjk/uy6;->OooOOOO:Z

    xor-int/2addr v0, v4

    iput-boolean v0, p1, Llyiahf/vczjk/hl1;->OooOOO:Z

    :cond_6
    :goto_3
    return-void

    :cond_7
    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-direct {p1, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
