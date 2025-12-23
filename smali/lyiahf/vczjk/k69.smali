.class public final Llyiahf/vczjk/k69;
.super Llyiahf/vczjk/my;
.source "SourceFile"


# static fields
.field public static final OooOOO:Llyiahf/vczjk/k69;


# instance fields
.field protected final _elementSerializer:Llyiahf/vczjk/zb4;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/zb4;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 1

    sget-object v0, Llyiahf/vczjk/a4a;->OooOOO:Llyiahf/vczjk/a4a;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-class v0, Ljava/lang/String;

    invoke-static {v0}, Llyiahf/vczjk/a4a;->OooOOOO(Ljava/lang/Class;)V

    new-instance v0, Llyiahf/vczjk/k69;

    invoke-direct {v0}, Llyiahf/vczjk/k69;-><init>()V

    sput-object v0, Llyiahf/vczjk/k69;->OooOOO:Llyiahf/vczjk/k69;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    const-class v0, [Ljava/lang/String;

    invoke-direct {p0, v0}, Llyiahf/vczjk/my;-><init>(Ljava/lang/Class;)V

    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/k69;->_elementSerializer:Llyiahf/vczjk/zb4;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/k69;Llyiahf/vczjk/db0;Llyiahf/vczjk/zb4;Ljava/lang/Boolean;)V
    .locals 0

    invoke-direct {p0, p1, p2, p4}, Llyiahf/vczjk/my;-><init>(Llyiahf/vczjk/my;Llyiahf/vczjk/db0;Ljava/lang/Boolean;)V

    iput-object p3, p0, Llyiahf/vczjk/k69;->_elementSerializer:Llyiahf/vczjk/zb4;

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;
    .locals 4

    const/4 v0, 0x0

    if-eqz p2, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/tg8;->o0O0O00()Llyiahf/vczjk/yn;

    move-result-object v1

    invoke-interface {p2}, Llyiahf/vczjk/db0;->OooO00o()Llyiahf/vczjk/pm;

    move-result-object v2

    if-eqz v2, :cond_0

    invoke-virtual {v1, v2}, Llyiahf/vczjk/yn;->OooO0Oo(Llyiahf/vczjk/u34;)Ljava/lang/Object;

    move-result-object v1

    if-eqz v1, :cond_0

    invoke-virtual {p1, v2, v1}, Llyiahf/vczjk/tg8;->o0000(Llyiahf/vczjk/u34;Ljava/lang/Object;)Llyiahf/vczjk/zb4;

    move-result-object v1

    goto :goto_0

    :cond_0
    move-object v1, v0

    :goto_0
    sget-object v2, Llyiahf/vczjk/n94;->OooOOOO:Llyiahf/vczjk/n94;

    const-class v3, [Ljava/lang/String;

    invoke-static {p1, p2, v3}, Llyiahf/vczjk/b59;->OooOO0O(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;Ljava/lang/Class;)Llyiahf/vczjk/q94;

    move-result-object v3

    if-eqz v3, :cond_1

    invoke-virtual {v3, v2}, Llyiahf/vczjk/q94;->OooO0O0(Llyiahf/vczjk/n94;)Ljava/lang/Boolean;

    move-result-object v2

    goto :goto_1

    :cond_1
    move-object v2, v0

    :goto_1
    if-nez v1, :cond_2

    iget-object v1, p0, Llyiahf/vczjk/k69;->_elementSerializer:Llyiahf/vczjk/zb4;

    :cond_2
    invoke-static {p1, p2, v1}, Llyiahf/vczjk/b59;->OooOO0(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;Llyiahf/vczjk/zb4;)Llyiahf/vczjk/zb4;

    move-result-object v1

    if-nez v1, :cond_3

    const-class v1, Ljava/lang/String;

    invoke-virtual {p1, v1, p2}, Llyiahf/vczjk/tg8;->o00Oo0(Ljava/lang/Class;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object v1

    :cond_3
    invoke-static {v1}, Llyiahf/vczjk/vy0;->OooOOoo(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_4

    goto :goto_2

    :cond_4
    move-object v0, v1

    :goto_2
    iget-object p1, p0, Llyiahf/vczjk/k69;->_elementSerializer:Llyiahf/vczjk/zb4;

    if-ne v0, p1, :cond_5

    iget-object p1, p0, Llyiahf/vczjk/my;->_unwrapSingle:Ljava/lang/Boolean;

    if-ne v2, p1, :cond_5

    return-object p0

    :cond_5
    new-instance p1, Llyiahf/vczjk/k69;

    invoke-direct {p1, p0, p2, v0, v2}, Llyiahf/vczjk/k69;-><init>(Llyiahf/vczjk/k69;Llyiahf/vczjk/db0;Llyiahf/vczjk/zb4;Ljava/lang/Boolean;)V

    return-object p1
.end method

.method public final OooO0Oo(Llyiahf/vczjk/tg8;Ljava/lang/Object;)Z
    .locals 0

    check-cast p2, [Ljava/lang/String;

    array-length p1, p2

    if-nez p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 3

    check-cast p1, [Ljava/lang/String;

    array-length v0, p1

    const/4 v1, 0x1

    if-ne v0, v1, :cond_2

    iget-object v1, p0, Llyiahf/vczjk/my;->_unwrapSingle:Ljava/lang/Boolean;

    if-nez v1, :cond_0

    sget-object v1, Llyiahf/vczjk/ig8;->OooOooO:Llyiahf/vczjk/ig8;

    invoke-virtual {p3, v1}, Llyiahf/vczjk/tg8;->o0000Ooo(Llyiahf/vczjk/ig8;)Z

    move-result v1

    if-nez v1, :cond_1

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/my;->_unwrapSingle:Ljava/lang/Boolean;

    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    if-ne v1, v2, :cond_2

    :cond_1
    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/k69;->OooOOo([Ljava/lang/String;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void

    :cond_2
    invoke-virtual {p2, v0, p1}, Llyiahf/vczjk/u94;->o0000o0O(ILjava/lang/Object;)V

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/k69;->OooOOo([Ljava/lang/String;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    invoke-virtual {p2}, Llyiahf/vczjk/u94;->o00000O()V

    return-void
.end method

.method public final OooOOO(Llyiahf/vczjk/d5a;)Llyiahf/vczjk/em1;
    .locals 0

    return-object p0
.end method

.method public final OooOOOo(Llyiahf/vczjk/db0;Ljava/lang/Boolean;)Llyiahf/vczjk/zb4;
    .locals 2

    new-instance v0, Llyiahf/vczjk/k69;

    iget-object v1, p0, Llyiahf/vczjk/k69;->_elementSerializer:Llyiahf/vczjk/zb4;

    invoke-direct {v0, p0, p1, v1, p2}, Llyiahf/vczjk/k69;-><init>(Llyiahf/vczjk/k69;Llyiahf/vczjk/db0;Llyiahf/vczjk/zb4;Ljava/lang/Boolean;)V

    return-object v0
.end method

.method public final OooOOo([Ljava/lang/String;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 4

    array-length v0, p1

    if-nez v0, :cond_0

    goto :goto_4

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/k69;->_elementSerializer:Llyiahf/vczjk/zb4;

    const/4 v2, 0x0

    if-eqz v1, :cond_2

    array-length v0, p1

    :goto_0
    if-ge v2, v0, :cond_4

    aget-object v3, p1, v2

    if-nez v3, :cond_1

    invoke-virtual {p3, p2}, Llyiahf/vczjk/tg8;->o00O0O(Llyiahf/vczjk/u94;)V

    goto :goto_1

    :cond_1
    invoke-virtual {v1, v3, p2, p3}, Llyiahf/vczjk/zb4;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    :goto_1
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_2
    :goto_2
    if-ge v2, v0, :cond_4

    aget-object p3, p1, v2

    if-nez p3, :cond_3

    invoke-virtual {p2}, Llyiahf/vczjk/u94;->o00000oo()V

    goto :goto_3

    :cond_3
    invoke-virtual {p2, p3}, Llyiahf/vczjk/u94;->o0000ooO(Ljava/lang/String;)V

    :goto_3
    add-int/lit8 v2, v2, 0x1

    goto :goto_2

    :cond_4
    :goto_4
    return-void
.end method

.method public final bridge synthetic OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 0

    check-cast p1, [Ljava/lang/String;

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/k69;->OooOOo([Ljava/lang/String;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void
.end method
