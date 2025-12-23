.class public Llyiahf/vczjk/cb0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/db0;
.implements Ljava/io/Serializable;


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _member:Llyiahf/vczjk/pm;

.field protected final _metadata:Llyiahf/vczjk/wa7;

.field protected final _name:Llyiahf/vczjk/xa7;

.field protected final _type:Llyiahf/vczjk/x64;

.field protected final _wrapperName:Llyiahf/vczjk/xa7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xa7;Llyiahf/vczjk/x64;Llyiahf/vczjk/xa7;Llyiahf/vczjk/pm;Llyiahf/vczjk/wa7;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/cb0;->_name:Llyiahf/vczjk/xa7;

    iput-object p2, p0, Llyiahf/vczjk/cb0;->_type:Llyiahf/vczjk/x64;

    iput-object p3, p0, Llyiahf/vczjk/cb0;->_wrapperName:Llyiahf/vczjk/xa7;

    iput-object p5, p0, Llyiahf/vczjk/cb0;->_metadata:Llyiahf/vczjk/wa7;

    iput-object p4, p0, Llyiahf/vczjk/cb0;->_member:Llyiahf/vczjk/pm;

    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/pm;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/cb0;->_member:Llyiahf/vczjk/pm;

    return-object v0
.end method

.method public final OooO0O0()Llyiahf/vczjk/wa7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/cb0;->_metadata:Llyiahf/vczjk/wa7;

    return-object v0
.end method

.method public final OooO0OO(Ljava/lang/Class;Llyiahf/vczjk/fc5;)Llyiahf/vczjk/q94;
    .locals 1

    invoke-virtual {p2, p1}, Llyiahf/vczjk/fc5;->OooO(Ljava/lang/Class;)Llyiahf/vczjk/q94;

    move-result-object p1

    invoke-virtual {p2}, Llyiahf/vczjk/ec5;->OooO0o0()Llyiahf/vczjk/yn;

    move-result-object p2

    if-eqz p2, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/cb0;->_member:Llyiahf/vczjk/pm;

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p2, v0}, Llyiahf/vczjk/yn;->OooOOO(Llyiahf/vczjk/u34;)Llyiahf/vczjk/q94;

    move-result-object p2

    if-nez p2, :cond_1

    goto :goto_0

    :cond_1
    invoke-virtual {p1, p2}, Llyiahf/vczjk/q94;->OooOO0o(Llyiahf/vczjk/q94;)Llyiahf/vczjk/q94;

    move-result-object p1

    :cond_2
    :goto_0
    return-object p1
.end method

.method public final OooO0Oo(Llyiahf/vczjk/gg8;Ljava/lang/Class;)Llyiahf/vczjk/fa4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/cb0;->_type:Llyiahf/vczjk/x64;

    iget-object v0, v0, Llyiahf/vczjk/x64;->_class:Ljava/lang/Class;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/fc5;->OooOo(Ljava/lang/Class;)Llyiahf/vczjk/uh1;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/fc5;->OooOoO(Ljava/lang/Class;)Llyiahf/vczjk/fa4;

    move-result-object p2

    const/4 v0, 0x0

    if-nez p2, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p2, v0}, Llyiahf/vczjk/fa4;->OooO0Oo(Llyiahf/vczjk/fa4;)Llyiahf/vczjk/fa4;

    move-result-object v0

    :goto_0
    invoke-virtual {p1}, Llyiahf/vczjk/ec5;->OooO0o0()Llyiahf/vczjk/yn;

    move-result-object p1

    if-eqz p1, :cond_2

    iget-object p2, p0, Llyiahf/vczjk/cb0;->_member:Llyiahf/vczjk/pm;

    if-nez p2, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {p1, p2}, Llyiahf/vczjk/yn;->Oooo0(Llyiahf/vczjk/u34;)Llyiahf/vczjk/fa4;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fa4;->OooO0Oo(Llyiahf/vczjk/fa4;)Llyiahf/vczjk/fa4;

    move-result-object p1

    return-object p1

    :cond_2
    :goto_1
    return-object v0
.end method

.method public final getFullName()Llyiahf/vczjk/xa7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/cb0;->_name:Llyiahf/vczjk/xa7;

    return-object v0
.end method

.method public final getName()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/cb0;->_name:Llyiahf/vczjk/xa7;

    iget-object v0, v0, Llyiahf/vczjk/xa7;->_simpleName:Ljava/lang/String;

    return-object v0
.end method

.method public final getType()Llyiahf/vczjk/x64;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/cb0;->_type:Llyiahf/vczjk/x64;

    return-object v0
.end method
