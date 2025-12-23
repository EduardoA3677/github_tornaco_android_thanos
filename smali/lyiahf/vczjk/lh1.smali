.class public abstract Llyiahf/vczjk/lh1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/db0;
.implements Ljava/io/Serializable;


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field public transient OooOOO0:Ljava/util/List;

.field protected final _metadata:Llyiahf/vczjk/wa7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lh1;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iget-object p1, p1, Llyiahf/vczjk/lh1;->_metadata:Llyiahf/vczjk/wa7;

    iput-object p1, p0, Llyiahf/vczjk/lh1;->_metadata:Llyiahf/vczjk/wa7;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/wa7;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    if-nez p1, :cond_0

    sget-object p1, Llyiahf/vczjk/wa7;->OooOOOo:Llyiahf/vczjk/wa7;

    :cond_0
    iput-object p1, p0, Llyiahf/vczjk/lh1;->_metadata:Llyiahf/vczjk/wa7;

    return-void
.end method


# virtual methods
.method public OooO0O0()Llyiahf/vczjk/wa7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/lh1;->_metadata:Llyiahf/vczjk/wa7;

    return-object v0
.end method

.method public final OooO0OO(Ljava/lang/Class;Llyiahf/vczjk/fc5;)Llyiahf/vczjk/q94;
    .locals 1

    invoke-virtual {p2, p1}, Llyiahf/vczjk/fc5;->OooO(Ljava/lang/Class;)Llyiahf/vczjk/q94;

    move-result-object p1

    invoke-virtual {p2}, Llyiahf/vczjk/ec5;->OooO0o0()Llyiahf/vczjk/yn;

    move-result-object p2

    if-eqz p2, :cond_0

    invoke-interface {p0}, Llyiahf/vczjk/db0;->OooO00o()Llyiahf/vczjk/pm;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {p2, v0}, Llyiahf/vczjk/yn;->OooOOO(Llyiahf/vczjk/u34;)Llyiahf/vczjk/q94;

    move-result-object p2

    goto :goto_0

    :cond_0
    const/4 p2, 0x0

    :goto_0
    if-nez p1, :cond_2

    if-nez p2, :cond_1

    sget-object p1, Llyiahf/vczjk/db0;->OooO00o:Llyiahf/vczjk/q94;

    return-object p1

    :cond_1
    return-object p2

    :cond_2
    if-nez p2, :cond_3

    return-object p1

    :cond_3
    invoke-virtual {p1, p2}, Llyiahf/vczjk/q94;->OooOO0o(Llyiahf/vczjk/q94;)Llyiahf/vczjk/q94;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0Oo(Llyiahf/vczjk/gg8;Ljava/lang/Class;)Llyiahf/vczjk/fa4;
    .locals 3

    invoke-virtual {p1}, Llyiahf/vczjk/ec5;->OooO0o0()Llyiahf/vczjk/yn;

    move-result-object v0

    invoke-interface {p0}, Llyiahf/vczjk/db0;->OooO00o()Llyiahf/vczjk/pm;

    move-result-object v1

    if-nez v1, :cond_0

    invoke-virtual {p1, p2}, Llyiahf/vczjk/fc5;->OooOoO(Ljava/lang/Class;)Llyiahf/vczjk/fa4;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-virtual {v1}, Llyiahf/vczjk/u34;->OooOoOO()Ljava/lang/Class;

    move-result-object v2

    invoke-virtual {p1, v2}, Llyiahf/vczjk/fc5;->OooOo(Ljava/lang/Class;)Llyiahf/vczjk/uh1;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/fc5;->OooOoO(Ljava/lang/Class;)Llyiahf/vczjk/fa4;

    move-result-object p1

    const/4 p2, 0x0

    if-nez p1, :cond_1

    goto :goto_0

    :cond_1
    invoke-virtual {p1, p2}, Llyiahf/vczjk/fa4;->OooO0Oo(Llyiahf/vczjk/fa4;)Llyiahf/vczjk/fa4;

    move-result-object p2

    :goto_0
    if-nez v0, :cond_2

    return-object p2

    :cond_2
    invoke-virtual {v0, v1}, Llyiahf/vczjk/yn;->Oooo0(Llyiahf/vczjk/u34;)Llyiahf/vczjk/fa4;

    move-result-object p1

    if-nez p2, :cond_3

    return-object p1

    :cond_3
    invoke-virtual {p2, p1}, Llyiahf/vczjk/fa4;->OooO0Oo(Llyiahf/vczjk/fa4;)Llyiahf/vczjk/fa4;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0o0()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/lh1;->_metadata:Llyiahf/vczjk/wa7;

    iget-object v0, v0, Llyiahf/vczjk/wa7;->_required:Ljava/lang/Boolean;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    return v0
.end method
