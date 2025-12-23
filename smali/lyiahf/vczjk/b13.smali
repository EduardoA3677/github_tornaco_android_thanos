.class public final Llyiahf/vczjk/b13;
.super Llyiahf/vczjk/gb0;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _delegate:Llyiahf/vczjk/gb0;

.field protected final _view:Ljava/lang/Class;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Class<",
            "*>;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ljava/lang/Class;Llyiahf/vczjk/gb0;)V
    .locals 0

    invoke-direct {p0, p2}, Llyiahf/vczjk/gb0;-><init>(Llyiahf/vczjk/gb0;)V

    iput-object p2, p0, Llyiahf/vczjk/b13;->_delegate:Llyiahf/vczjk/gb0;

    iput-object p1, p0, Llyiahf/vczjk/b13;->_view:Ljava/lang/Class;

    return-void
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/zb4;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b13;->_delegate:Llyiahf/vczjk/gb0;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/gb0;->OooO(Llyiahf/vczjk/zb4;)V

    return-void
.end method

.method public final OooO0oo(Llyiahf/vczjk/zb4;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b13;->_delegate:Llyiahf/vczjk/gb0;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/gb0;->OooO0oo(Llyiahf/vczjk/zb4;)V

    return-void
.end method

.method public final OooOO0(Llyiahf/vczjk/wt5;)Llyiahf/vczjk/gb0;
    .locals 2

    new-instance v0, Llyiahf/vczjk/b13;

    iget-object v1, p0, Llyiahf/vczjk/b13;->_delegate:Llyiahf/vczjk/gb0;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/gb0;->OooOO0(Llyiahf/vczjk/wt5;)Llyiahf/vczjk/gb0;

    move-result-object p1

    iget-object v1, p0, Llyiahf/vczjk/b13;->_view:Ljava/lang/Class;

    invoke-direct {v0, v1, p1}, Llyiahf/vczjk/b13;-><init>(Ljava/lang/Class;Llyiahf/vczjk/gb0;)V

    return-object v0
.end method

.method public final OooOO0O(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 2

    invoke-virtual {p3}, Llyiahf/vczjk/tg8;->oo0o0Oo()Ljava/lang/Class;

    move-result-object v0

    if-eqz v0, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/b13;->_view:Ljava/lang/Class;

    invoke-virtual {v1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/b13;->_delegate:Llyiahf/vczjk/gb0;

    invoke-virtual {p1, p2, p3}, Llyiahf/vczjk/gb0;->OooOOO0(Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void

    :cond_1
    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/b13;->_delegate:Llyiahf/vczjk/gb0;

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/gb0;->OooOO0O(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void
.end method

.method public final OooOO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 2

    invoke-virtual {p3}, Llyiahf/vczjk/tg8;->oo0o0Oo()Ljava/lang/Class;

    move-result-object v0

    if-eqz v0, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/b13;->_view:Ljava/lang/Class;

    invoke-virtual {v1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/b13;->_delegate:Llyiahf/vczjk/gb0;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    return-void

    :cond_1
    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/b13;->_delegate:Llyiahf/vczjk/gb0;

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/gb0;->OooOO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void
.end method
