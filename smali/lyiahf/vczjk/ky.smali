.class public final Llyiahf/vczjk/ky;
.super Llyiahf/vczjk/dm1;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field private final _children:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Llyiahf/vczjk/qa4;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ua4;)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/dm1;-><init>(Llyiahf/vczjk/ua4;)V

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ky;->_children:Ljava/util/List;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/ky;->_children:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->size()I

    move-result v1

    invoke-virtual {p1, v1, p0}, Llyiahf/vczjk/u94;->o0000o0O(ILjava/lang/Object;)V

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v1, :cond_0

    invoke-interface {v0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/qa4;

    check-cast v3, Llyiahf/vczjk/y70;

    invoke-virtual {v3, p1, p2}, Llyiahf/vczjk/y70;->OooO00o(Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/u94;->o00000O()V

    return-void
.end method

.method public final OooO0O0(Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V
    .locals 3

    sget-object v0, Llyiahf/vczjk/gc4;->OooOOOo:Llyiahf/vczjk/gc4;

    invoke-virtual {p3, p0, v0}, Llyiahf/vczjk/d5a;->OooO0Oo(Ljava/lang/Object;Llyiahf/vczjk/gc4;)Llyiahf/vczjk/rsa;

    move-result-object v0

    invoke-virtual {p3, p1, v0}, Llyiahf/vczjk/d5a;->OooO0o0(Llyiahf/vczjk/u94;Llyiahf/vczjk/rsa;)Llyiahf/vczjk/rsa;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/ky;->_children:Ljava/util/List;

    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_0

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/qa4;

    check-cast v2, Llyiahf/vczjk/y70;

    invoke-virtual {v2, p1, p2}, Llyiahf/vczjk/y70;->OooO00o(Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    goto :goto_0

    :cond_0
    invoke-virtual {p3, p1, v0}, Llyiahf/vczjk/d5a;->OooO0o(Llyiahf/vczjk/u94;Llyiahf/vczjk/rsa;)Llyiahf/vczjk/rsa;

    return-void
.end method

.method public final OooO0OO()Ljava/util/Iterator;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ky;->_children:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0o(Llyiahf/vczjk/qa4;)V
    .locals 1

    if-nez p1, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/dm1;->_nodeFactory:Llyiahf/vczjk/ua4;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object p1, Llyiahf/vczjk/p46;->OooOOO0:Llyiahf/vczjk/p46;

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/ky;->_children:Ljava/util/List;

    invoke-interface {v0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    if-ne p1, p0, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 v0, 0x0

    if-nez p1, :cond_1

    return v0

    :cond_1
    instance-of v1, p1, Llyiahf/vczjk/ky;

    if-eqz v1, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/ky;->_children:Ljava/util/List;

    check-cast p1, Llyiahf/vczjk/ky;

    iget-object p1, p1, Llyiahf/vczjk/ky;->_children:Ljava/util/List;

    invoke-interface {v0, p1}, Ljava/util/List;->equals(Ljava/lang/Object;)Z

    move-result p1

    return p1

    :cond_2
    return v0
.end method

.method public final hashCode()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ky;->_children:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->hashCode()I

    move-result v0

    return v0
.end method

.method public final isEmpty()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ky;->_children:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    return v0
.end method
