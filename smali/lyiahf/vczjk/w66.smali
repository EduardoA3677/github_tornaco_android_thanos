.class public final Llyiahf/vczjk/w66;
.super Llyiahf/vczjk/ph8;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field private final _forward:Llyiahf/vczjk/ph8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ph8;Llyiahf/vczjk/t66;)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/ph8;-><init>(Llyiahf/vczjk/ph8;)V

    iput-object p1, p0, Llyiahf/vczjk/w66;->_forward:Llyiahf/vczjk/ph8;

    iput-object p2, p0, Llyiahf/vczjk/ph8;->_objectIdInfo:Llyiahf/vczjk/t66;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/w66;Llyiahf/vczjk/e94;Llyiahf/vczjk/u46;)V
    .locals 0

    invoke-direct {p0, p1, p2, p3}, Llyiahf/vczjk/ph8;-><init>(Llyiahf/vczjk/ph8;Llyiahf/vczjk/e94;Llyiahf/vczjk/u46;)V

    iget-object p2, p1, Llyiahf/vczjk/w66;->_forward:Llyiahf/vczjk/ph8;

    iput-object p2, p0, Llyiahf/vczjk/w66;->_forward:Llyiahf/vczjk/ph8;

    iget-object p1, p1, Llyiahf/vczjk/ph8;->_objectIdInfo:Llyiahf/vczjk/t66;

    iput-object p1, p0, Llyiahf/vczjk/ph8;->_objectIdInfo:Llyiahf/vczjk/t66;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/w66;Llyiahf/vczjk/xa7;)V
    .locals 0

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/ph8;-><init>(Llyiahf/vczjk/ph8;Llyiahf/vczjk/xa7;)V

    iget-object p2, p1, Llyiahf/vczjk/w66;->_forward:Llyiahf/vczjk/ph8;

    iput-object p2, p0, Llyiahf/vczjk/w66;->_forward:Llyiahf/vczjk/ph8;

    iget-object p1, p1, Llyiahf/vczjk/ph8;->_objectIdInfo:Llyiahf/vczjk/t66;

    iput-object p1, p0, Llyiahf/vczjk/ph8;->_objectIdInfo:Llyiahf/vczjk/t66;

    return-void
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)V
    .locals 0

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/w66;->OooOO0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public final OooO00o()Llyiahf/vczjk/pm;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/w66;->_forward:Llyiahf/vczjk/ph8;

    invoke-interface {v0}, Llyiahf/vczjk/db0;->OooO00o()Llyiahf/vczjk/pm;

    move-result-object v0

    return-object v0
.end method

.method public final OooOO0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    :try_start_0
    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/ph8;->OooO0oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p2

    iget-object v0, p0, Llyiahf/vczjk/w66;->_forward:Llyiahf/vczjk/ph8;

    invoke-virtual {v0, p3, p2}, Llyiahf/vczjk/ph8;->OooOoO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1
    :try_end_0
    .catch Llyiahf/vczjk/l9a; {:try_start_0 .. :try_end_0} :catch_0

    return-object p1

    :catch_0
    move-exception p2

    iget-object v0, p0, Llyiahf/vczjk/ph8;->_objectIdInfo:Llyiahf/vczjk/t66;

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v0}, Llyiahf/vczjk/e94;->OooOO0o()Llyiahf/vczjk/u66;

    move-result-object v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    new-instance p3, Llyiahf/vczjk/na4;

    const-string v0, "Unresolved forward reference but no identity info"

    invoke-direct {p3, p1, v0, p2}, Llyiahf/vczjk/na4;-><init>(Ljava/io/Closeable;Ljava/lang/String;Ljava/lang/Throwable;)V

    throw p3

    :cond_1
    :goto_0
    invoke-virtual {p2}, Llyiahf/vczjk/l9a;->OooOO0()Llyiahf/vczjk/bh7;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/v66;

    iget-object v1, p0, Llyiahf/vczjk/ph8;->_type:Llyiahf/vczjk/x64;

    invoke-virtual {v1}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v1

    invoke-direct {v0, p0, p2, v1, p3}, Llyiahf/vczjk/v66;-><init>(Llyiahf/vczjk/w66;Llyiahf/vczjk/l9a;Ljava/lang/Class;Ljava/lang/Object;)V

    invoke-virtual {p1, v0}, Llyiahf/vczjk/bh7;->OooO00o(Llyiahf/vczjk/ah7;)V

    const/4 p1, 0x0

    return-object p1
.end method

.method public final OooOO0o(Llyiahf/vczjk/t72;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/w66;->_forward:Llyiahf/vczjk/ph8;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ph8;->OooOO0o(Llyiahf/vczjk/t72;)V

    :cond_0
    return-void
.end method

.method public final OooOOO0()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/w66;->_forward:Llyiahf/vczjk/ph8;

    invoke-virtual {v0}, Llyiahf/vczjk/ph8;->OooOOO0()I

    move-result v0

    return v0
.end method

.method public final OooOoO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/w66;->_forward:Llyiahf/vczjk/ph8;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/ph8;->OooOoO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooOoO0(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/w66;->_forward:Llyiahf/vczjk/ph8;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/ph8;->OooOoO0(Ljava/lang/Object;Ljava/lang/Object;)V

    return-void
.end method

.method public final OooOoo(Llyiahf/vczjk/xa7;)Llyiahf/vczjk/ph8;
    .locals 1

    new-instance v0, Llyiahf/vczjk/w66;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/w66;-><init>(Llyiahf/vczjk/w66;Llyiahf/vczjk/xa7;)V

    return-object v0
.end method

.method public final OooOooO(Llyiahf/vczjk/u46;)Llyiahf/vczjk/ph8;
    .locals 2

    new-instance v0, Llyiahf/vczjk/w66;

    iget-object v1, p0, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-direct {v0, p0, v1, p1}, Llyiahf/vczjk/w66;-><init>(Llyiahf/vczjk/w66;Llyiahf/vczjk/e94;Llyiahf/vczjk/u46;)V

    return-object v0
.end method

.method public final Oooo000(Llyiahf/vczjk/e94;)Llyiahf/vczjk/ph8;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    if-ne v0, p1, :cond_0

    return-object p0

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/ph8;->_nullProvider:Llyiahf/vczjk/u46;

    if-ne v0, v1, :cond_1

    move-object v1, p1

    :cond_1
    new-instance v0, Llyiahf/vczjk/w66;

    invoke-direct {v0, p0, p1, v1}, Llyiahf/vczjk/w66;-><init>(Llyiahf/vczjk/w66;Llyiahf/vczjk/e94;Llyiahf/vczjk/u46;)V

    return-object v0
.end method
