.class public final Llyiahf/vczjk/mi5;
.super Llyiahf/vczjk/oh8;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _accessor:Llyiahf/vczjk/pm;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ph8;Llyiahf/vczjk/pm;)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/oh8;-><init>(Llyiahf/vczjk/ph8;)V

    iput-object p2, p0, Llyiahf/vczjk/mi5;->_accessor:Llyiahf/vczjk/pm;

    return-void
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/mi5;->_accessor:Llyiahf/vczjk/pm;

    invoke-virtual {v0, p3}, Llyiahf/vczjk/pm;->o0ooOOo(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    if-nez v0, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/oh8;->delegate:Llyiahf/vczjk/ph8;

    invoke-virtual {v1, p2, p1}, Llyiahf/vczjk/ph8;->OooO0oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    goto :goto_0

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/oh8;->delegate:Llyiahf/vczjk/ph8;

    invoke-virtual {v1, p1, p2, v0}, Llyiahf/vczjk/ph8;->OooOO0O(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    :goto_0
    if-eq p1, v0, :cond_1

    iget-object p2, p0, Llyiahf/vczjk/oh8;->delegate:Llyiahf/vczjk/ph8;

    invoke-virtual {p2, p3, p1}, Llyiahf/vczjk/ph8;->OooOoO0(Ljava/lang/Object;Ljava/lang/Object;)V

    :cond_1
    return-void
.end method

.method public final OooOO0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/mi5;->_accessor:Llyiahf/vczjk/pm;

    invoke-virtual {v0, p3}, Llyiahf/vczjk/pm;->o0ooOOo(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    if-nez v0, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/oh8;->delegate:Llyiahf/vczjk/ph8;

    invoke-virtual {v1, p2, p1}, Llyiahf/vczjk/ph8;->OooO0oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    goto :goto_0

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/oh8;->delegate:Llyiahf/vczjk/ph8;

    invoke-virtual {v1, p1, p2, v0}, Llyiahf/vczjk/ph8;->OooOO0O(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    :goto_0
    if-eq p1, v0, :cond_1

    if-eqz p1, :cond_1

    iget-object p2, p0, Llyiahf/vczjk/oh8;->delegate:Llyiahf/vczjk/ph8;

    invoke-virtual {p2, p3, p1}, Llyiahf/vczjk/ph8;->OooOoO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_1
    return-object p3
.end method

.method public final OooOoO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    if-eqz p2, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/oh8;->delegate:Llyiahf/vczjk/ph8;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/ph8;->OooOoO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    :cond_0
    return-object p1
.end method

.method public final OooOoO0(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 1

    if-eqz p2, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/oh8;->delegate:Llyiahf/vczjk/ph8;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/ph8;->OooOoO0(Ljava/lang/Object;Ljava/lang/Object;)V

    :cond_0
    return-void
.end method

.method public final Oooo00O(Llyiahf/vczjk/ph8;)Llyiahf/vczjk/ph8;
    .locals 2

    new-instance v0, Llyiahf/vczjk/mi5;

    iget-object v1, p0, Llyiahf/vczjk/mi5;->_accessor:Llyiahf/vczjk/pm;

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/mi5;-><init>(Llyiahf/vczjk/ph8;Llyiahf/vczjk/pm;)V

    return-object v0
.end method
