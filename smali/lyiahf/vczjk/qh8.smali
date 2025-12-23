.class public final Llyiahf/vczjk/qh8;
.super Llyiahf/vczjk/ph8;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _annotated:Llyiahf/vczjk/rm;

.field protected final _getter:Ljava/lang/reflect/Method;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/eb0;Llyiahf/vczjk/x64;Llyiahf/vczjk/u3a;Llyiahf/vczjk/lo;Llyiahf/vczjk/rm;)V
    .locals 0

    invoke-direct {p0, p1, p2, p3, p4}, Llyiahf/vczjk/ph8;-><init>(Llyiahf/vczjk/eb0;Llyiahf/vczjk/x64;Llyiahf/vczjk/u3a;Llyiahf/vczjk/lo;)V

    iput-object p5, p0, Llyiahf/vczjk/qh8;->_annotated:Llyiahf/vczjk/rm;

    iget-object p1, p5, Llyiahf/vczjk/rm;->OooOo0o:Ljava/lang/reflect/Method;

    iput-object p1, p0, Llyiahf/vczjk/qh8;->_getter:Ljava/lang/reflect/Method;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/qh8;Llyiahf/vczjk/e94;Llyiahf/vczjk/u46;)V
    .locals 0

    invoke-direct {p0, p1, p2, p3}, Llyiahf/vczjk/ph8;-><init>(Llyiahf/vczjk/ph8;Llyiahf/vczjk/e94;Llyiahf/vczjk/u46;)V

    iget-object p2, p1, Llyiahf/vczjk/qh8;->_annotated:Llyiahf/vczjk/rm;

    iput-object p2, p0, Llyiahf/vczjk/qh8;->_annotated:Llyiahf/vczjk/rm;

    iget-object p1, p1, Llyiahf/vczjk/qh8;->_getter:Ljava/lang/reflect/Method;

    iput-object p1, p0, Llyiahf/vczjk/qh8;->_getter:Ljava/lang/reflect/Method;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/qh8;Llyiahf/vczjk/xa7;)V
    .locals 0

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/ph8;-><init>(Llyiahf/vczjk/ph8;Llyiahf/vczjk/xa7;)V

    iget-object p2, p1, Llyiahf/vczjk/qh8;->_annotated:Llyiahf/vczjk/rm;

    iput-object p2, p0, Llyiahf/vczjk/qh8;->_annotated:Llyiahf/vczjk/rm;

    iget-object p1, p1, Llyiahf/vczjk/qh8;->_getter:Ljava/lang/reflect/Method;

    iput-object p1, p0, Llyiahf/vczjk/qh8;->_getter:Ljava/lang/reflect/Method;

    return-void
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)V
    .locals 3

    sget-object v0, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/eb4;->o0000Oo(Llyiahf/vczjk/gc4;)Z

    move-result v0

    if-eqz v0, :cond_0

    return-void

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/ph8;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    const/4 v1, 0x0

    if-nez v0, :cond_2

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/qh8;->_getter:Ljava/lang/reflect/Method;

    invoke-virtual {v0, p3, v1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p3
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    if-eqz p3, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/e94;->OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;

    return-void

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/ph8;->getType()Llyiahf/vczjk/x64;

    move-result-object p1

    invoke-virtual {p0}, Llyiahf/vczjk/ph8;->getName()Ljava/lang/String;

    move-result-object p3

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v2, "Problem deserializing \'setterless\' property \'"

    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p3, "\': get method returned null"

    invoke-virtual {v0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p3

    invoke-virtual {p2, p1, p3}, Llyiahf/vczjk/v72;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    throw v1

    :catch_0
    move-exception p2

    invoke-static {p2}, Llyiahf/vczjk/vy0;->OooOoO0(Ljava/lang/Throwable;)V

    invoke-static {p2}, Llyiahf/vczjk/vy0;->OooOoO(Ljava/lang/Throwable;)V

    invoke-static {p2}, Llyiahf/vczjk/vy0;->OooOOOO(Ljava/lang/Exception;)Ljava/lang/Throwable;

    move-result-object p2

    invoke-static {p2}, Llyiahf/vczjk/vy0;->OooO0oo(Ljava/lang/Throwable;)Ljava/lang/String;

    move-result-object p3

    new-instance v0, Llyiahf/vczjk/na4;

    invoke-direct {v0, p1, p3, p2}, Llyiahf/vczjk/na4;-><init>(Ljava/io/Closeable;Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v0

    :cond_2
    invoke-virtual {p0}, Llyiahf/vczjk/ph8;->getType()Llyiahf/vczjk/x64;

    move-result-object p1

    invoke-virtual {p0}, Llyiahf/vczjk/ph8;->getName()Ljava/lang/String;

    move-result-object p3

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v2, "Problem deserializing \'setterless\' property (\""

    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p3, "\"): no way to handle typed deser with setterless yet"

    invoke-virtual {v0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p3

    invoke-virtual {p2, p1, p3}, Llyiahf/vczjk/v72;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    throw v1
.end method

.method public final OooO00o()Llyiahf/vczjk/pm;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/qh8;->_annotated:Llyiahf/vczjk/rm;

    return-object v0
.end method

.method public final OooOO0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/qh8;->OooO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)V

    return-object p3
.end method

.method public final OooOO0o(Llyiahf/vczjk/t72;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/qh8;->_annotated:Llyiahf/vczjk/rm;

    sget-object v1, Llyiahf/vczjk/gc5;->OooOoO:Llyiahf/vczjk/gc5;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/ec5;->OooOOoo(Llyiahf/vczjk/gc5;)Z

    move-result p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/pm;->oo000o(Z)V

    return-void
.end method

.method public final OooOoO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/qh8;->OooOoO0(Ljava/lang/Object;Ljava/lang/Object;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final OooOoO0(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 1

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    new-instance p2, Ljava/lang/StringBuilder;

    const-string v0, "Should never call `set()` on setterless property (\'"

    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/ph8;->getName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v0, "\')"

    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooOoo(Llyiahf/vczjk/xa7;)Llyiahf/vczjk/ph8;
    .locals 1

    new-instance v0, Llyiahf/vczjk/qh8;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/qh8;-><init>(Llyiahf/vczjk/qh8;Llyiahf/vczjk/xa7;)V

    return-object v0
.end method

.method public final OooOooO(Llyiahf/vczjk/u46;)Llyiahf/vczjk/ph8;
    .locals 2

    new-instance v0, Llyiahf/vczjk/qh8;

    iget-object v1, p0, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-direct {v0, p0, v1, p1}, Llyiahf/vczjk/qh8;-><init>(Llyiahf/vczjk/qh8;Llyiahf/vczjk/e94;Llyiahf/vczjk/u46;)V

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
    new-instance v0, Llyiahf/vczjk/qh8;

    invoke-direct {v0, p0, p1, v1}, Llyiahf/vczjk/qh8;-><init>(Llyiahf/vczjk/qh8;Llyiahf/vczjk/e94;Llyiahf/vczjk/u46;)V

    return-object v0
.end method
