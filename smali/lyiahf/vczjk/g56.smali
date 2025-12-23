.class public final Llyiahf/vczjk/g56;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/u46;
.implements Ljava/io/Serializable;


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _name:Llyiahf/vczjk/xa7;

.field protected final _type:Llyiahf/vczjk/x64;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xa7;Llyiahf/vczjk/x64;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/g56;->_name:Llyiahf/vczjk/xa7;

    iput-object p2, p0, Llyiahf/vczjk/g56;->_type:Llyiahf/vczjk/x64;

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/g56;->_name:Llyiahf/vczjk/xa7;

    iget-object v1, p0, Llyiahf/vczjk/g56;->_type:Llyiahf/vczjk/x64;

    invoke-static {p1, v0, v1}, Llyiahf/vczjk/g44;->OooO(Llyiahf/vczjk/v72;Llyiahf/vczjk/xa7;Llyiahf/vczjk/x64;)Llyiahf/vczjk/g44;

    move-result-object p1

    throw p1
.end method
