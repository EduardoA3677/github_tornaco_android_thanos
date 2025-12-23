.class public final Llyiahf/vczjk/m76;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/io/Serializable;


# static fields
.field public static final OooOOO0:Llyiahf/vczjk/ij5;

.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _config:Llyiahf/vczjk/gg8;

.field protected final _generatorFactory:Llyiahf/vczjk/l94;

.field protected final _generatorSettings:Llyiahf/vczjk/k76;

.field protected final _prefetch:Llyiahf/vczjk/l76;

.field protected final _serializerFactory:Llyiahf/vczjk/rg8;

.field protected final _serializerProvider:Llyiahf/vczjk/w32;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/ij5;

    sget-object v1, Llyiahf/vczjk/u37;->OooOO0:Llyiahf/vczjk/ng8;

    invoke-virtual {v1}, Llyiahf/vczjk/ng8;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object v1, v0, Llyiahf/vczjk/ij5;->_rootValueSeparator:Ljava/lang/String;

    sget-object v1, Llyiahf/vczjk/u37;->OooO:Llyiahf/vczjk/rf8;

    iput-object v1, v0, Llyiahf/vczjk/ij5;->_separators:Llyiahf/vczjk/rf8;

    sput-object v0, Llyiahf/vczjk/m76;->OooOOO0:Llyiahf/vczjk/ij5;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/e76;Llyiahf/vczjk/gg8;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/m76;->_config:Llyiahf/vczjk/gg8;

    iget-object p2, p1, Llyiahf/vczjk/e76;->_serializerProvider:Llyiahf/vczjk/w32;

    iput-object p2, p0, Llyiahf/vczjk/m76;->_serializerProvider:Llyiahf/vczjk/w32;

    iget-object p2, p1, Llyiahf/vczjk/e76;->_serializerFactory:Llyiahf/vczjk/rg8;

    iput-object p2, p0, Llyiahf/vczjk/m76;->_serializerFactory:Llyiahf/vczjk/rg8;

    iget-object p1, p1, Llyiahf/vczjk/e76;->_jsonFactory:Llyiahf/vczjk/l94;

    iput-object p1, p0, Llyiahf/vczjk/m76;->_generatorFactory:Llyiahf/vczjk/l94;

    sget-object p1, Llyiahf/vczjk/k76;->OooOOO0:Llyiahf/vczjk/k76;

    iput-object p1, p0, Llyiahf/vczjk/m76;->_generatorSettings:Llyiahf/vczjk/k76;

    sget-object p1, Llyiahf/vczjk/l76;->OooOOO0:Llyiahf/vczjk/l76;

    iput-object p1, p0, Llyiahf/vczjk/m76;->_prefetch:Llyiahf/vczjk/l76;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/m76;Llyiahf/vczjk/gg8;Llyiahf/vczjk/k76;Llyiahf/vczjk/l76;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/m76;->_config:Llyiahf/vczjk/gg8;

    iget-object p2, p1, Llyiahf/vczjk/m76;->_serializerProvider:Llyiahf/vczjk/w32;

    iput-object p2, p0, Llyiahf/vczjk/m76;->_serializerProvider:Llyiahf/vczjk/w32;

    iget-object p2, p1, Llyiahf/vczjk/m76;->_serializerFactory:Llyiahf/vczjk/rg8;

    iput-object p2, p0, Llyiahf/vczjk/m76;->_serializerFactory:Llyiahf/vczjk/rg8;

    iget-object p1, p1, Llyiahf/vczjk/m76;->_generatorFactory:Llyiahf/vczjk/l94;

    iput-object p1, p0, Llyiahf/vczjk/m76;->_generatorFactory:Llyiahf/vczjk/l94;

    iput-object p3, p0, Llyiahf/vczjk/m76;->_generatorSettings:Llyiahf/vczjk/k76;

    iput-object p4, p0, Llyiahf/vczjk/m76;->_prefetch:Llyiahf/vczjk/l76;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/u94;Llyiahf/vczjk/y70;)V
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/m76;->_config:Llyiahf/vczjk/gg8;

    sget-object v1, Llyiahf/vczjk/ig8;->OooOo00:Llyiahf/vczjk/ig8;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/gg8;->Oooo0(Llyiahf/vczjk/ig8;)Z

    move-result v0

    if-eqz v0, :cond_0

    instance-of v0, p2, Ljava/io/Closeable;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Ljava/io/Closeable;

    const/4 v1, 0x0

    :try_start_0
    iget-object v2, p0, Llyiahf/vczjk/m76;->_prefetch:Llyiahf/vczjk/l76;

    iget-object v3, p0, Llyiahf/vczjk/m76;->_serializerProvider:Llyiahf/vczjk/w32;

    iget-object v4, p0, Llyiahf/vczjk/m76;->_config:Llyiahf/vczjk/gg8;

    iget-object v5, p0, Llyiahf/vczjk/m76;->_serializerFactory:Llyiahf/vczjk/rg8;

    check-cast v3, Llyiahf/vczjk/v32;

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v6, Llyiahf/vczjk/v32;

    invoke-direct {v6, v3, v4, v5}, Llyiahf/vczjk/tg8;-><init>(Llyiahf/vczjk/tg8;Llyiahf/vczjk/gg8;Llyiahf/vczjk/rg8;)V

    invoke-virtual {v2, p1, p2, v6}, Llyiahf/vczjk/l76;->OooO00o(Llyiahf/vczjk/u94;Llyiahf/vczjk/y70;Llyiahf/vczjk/v32;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_1

    :try_start_1
    invoke-interface {v0}, Ljava/io/Closeable;->close()V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    invoke-virtual {p1}, Llyiahf/vczjk/u94;->close()V

    return-void

    :catch_0
    move-exception p2

    move-object v0, v1

    goto :goto_0

    :catch_1
    move-exception p2

    :goto_0
    invoke-static {p1, v0, p2}, Llyiahf/vczjk/vy0;->OooO0o(Llyiahf/vczjk/u94;Ljava/io/Closeable;Ljava/lang/Exception;)V

    throw v1

    :cond_0
    :try_start_2
    iget-object v0, p0, Llyiahf/vczjk/m76;->_prefetch:Llyiahf/vczjk/l76;

    iget-object v1, p0, Llyiahf/vczjk/m76;->_serializerProvider:Llyiahf/vczjk/w32;

    iget-object v2, p0, Llyiahf/vczjk/m76;->_config:Llyiahf/vczjk/gg8;

    iget-object v3, p0, Llyiahf/vczjk/m76;->_serializerFactory:Llyiahf/vczjk/rg8;

    check-cast v1, Llyiahf/vczjk/v32;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v4, Llyiahf/vczjk/v32;

    invoke-direct {v4, v1, v2, v3}, Llyiahf/vczjk/tg8;-><init>(Llyiahf/vczjk/tg8;Llyiahf/vczjk/gg8;Llyiahf/vczjk/rg8;)V

    invoke-virtual {v0, p1, p2, v4}, Llyiahf/vczjk/l76;->OooO00o(Llyiahf/vczjk/u94;Llyiahf/vczjk/y70;Llyiahf/vczjk/v32;)V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_2

    invoke-virtual {p1}, Llyiahf/vczjk/u94;->close()V

    return-void

    :catch_2
    move-exception p2

    sget-object v0, Llyiahf/vczjk/vy0;->OooO00o:[Ljava/lang/annotation/Annotation;

    sget-object v0, Llyiahf/vczjk/t94;->OooOOO:Llyiahf/vczjk/t94;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/u94;->OooOoO(Llyiahf/vczjk/t94;)Llyiahf/vczjk/u94;

    :try_start_3
    invoke-virtual {p1}, Llyiahf/vczjk/u94;->close()V
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_3

    goto :goto_1

    :catch_3
    move-exception p1

    invoke-virtual {p2, p1}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    :goto_1
    invoke-static {p2}, Llyiahf/vczjk/vy0;->OooOoO0(Ljava/lang/Throwable;)V

    invoke-static {p2}, Llyiahf/vczjk/vy0;->OooOoO(Ljava/lang/Throwable;)V

    new-instance p1, Ljava/lang/RuntimeException;

    invoke-direct {p1, p2}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    throw p1
.end method

.method public final OooO0O0(Llyiahf/vczjk/dd8;)Llyiahf/vczjk/u94;
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/m76;->_generatorFactory:Llyiahf/vczjk/l94;

    const/4 v1, 0x0

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/l94;->OooO00o(Ljava/lang/Object;Z)Llyiahf/vczjk/t01;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/ssa;

    iget v3, v0, Llyiahf/vczjk/l94;->_generatorFeatures:I

    iget-char v4, v0, Llyiahf/vczjk/l94;->_quoteChar:C

    invoke-direct {v2, v1, v3, p1, v4}, Llyiahf/vczjk/ssa;-><init>(Llyiahf/vczjk/t01;ILjava/io/Writer;C)V

    iget p1, v0, Llyiahf/vczjk/l94;->_maximumNonEscapedChar:I

    if-lez p1, :cond_0

    invoke-virtual {v2, p1}, Llyiahf/vczjk/v94;->OoooOoo(I)V

    :cond_0
    iget-object p1, v0, Llyiahf/vczjk/l94;->_rootValueSeparator:Llyiahf/vczjk/fg8;

    sget-object v0, Llyiahf/vczjk/l94;->OooOOo:Llyiahf/vczjk/ng8;

    if-eq p1, v0, :cond_1

    iput-object p1, v2, Llyiahf/vczjk/v94;->OooOo0:Llyiahf/vczjk/fg8;

    :cond_1
    iget-object p1, p0, Llyiahf/vczjk/m76;->_config:Llyiahf/vczjk/gg8;

    invoke-virtual {p1, v2}, Llyiahf/vczjk/gg8;->Oooo00O(Llyiahf/vczjk/u94;)V

    iget-object p1, p0, Llyiahf/vczjk/m76;->_generatorSettings:Llyiahf/vczjk/k76;

    iget-object v0, p1, Llyiahf/vczjk/k76;->prettyPrinter:Llyiahf/vczjk/u37;

    if-eqz v0, :cond_4

    sget-object v1, Llyiahf/vczjk/m76;->OooOOO0:Llyiahf/vczjk/ij5;

    if-ne v0, v1, :cond_2

    const/4 v0, 0x0

    invoke-virtual {v2, v0}, Llyiahf/vczjk/u94;->Oooooo0(Llyiahf/vczjk/u37;)V

    goto :goto_0

    :cond_2
    instance-of v1, v0, Llyiahf/vczjk/l14;

    if-eqz v1, :cond_3

    check-cast v0, Llyiahf/vczjk/l14;

    check-cast v0, Llyiahf/vczjk/j32;

    new-instance v1, Llyiahf/vczjk/j32;

    invoke-direct {v1, v0}, Llyiahf/vczjk/j32;-><init>(Llyiahf/vczjk/j32;)V

    move-object v0, v1

    :cond_3
    invoke-virtual {v2, v0}, Llyiahf/vczjk/u94;->Oooooo0(Llyiahf/vczjk/u37;)V

    :cond_4
    :goto_0
    iget-object p1, p1, Llyiahf/vczjk/k76;->rootValueSeparator:Llyiahf/vczjk/fg8;

    if-eqz p1, :cond_5

    invoke-virtual {v2, p1}, Llyiahf/vczjk/u94;->o0OoOo0(Llyiahf/vczjk/fg8;)V

    :cond_5
    return-object v2
.end method
