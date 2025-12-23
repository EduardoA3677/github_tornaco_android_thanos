.class public final Llyiahf/vczjk/yz3;
.super Llyiahf/vczjk/oh8;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field public final transient OooOOOO:Ljava/lang/reflect/Constructor;

.field protected _annotated:Llyiahf/vczjk/jm;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ph8;Ljava/lang/reflect/Constructor;)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/oh8;-><init>(Llyiahf/vczjk/ph8;)V

    iput-object p2, p0, Llyiahf/vczjk/yz3;->OooOOOO:Ljava/lang/reflect/Constructor;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/yz3;Llyiahf/vczjk/jm;)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/oh8;-><init>(Llyiahf/vczjk/ph8;)V

    iput-object p2, p0, Llyiahf/vczjk/yz3;->_annotated:Llyiahf/vczjk/jm;

    if-nez p2, :cond_0

    const/4 p1, 0x0

    goto :goto_0

    :cond_0
    iget-object p1, p2, Llyiahf/vczjk/jm;->_constructor:Ljava/lang/reflect/Constructor;

    :goto_0
    iput-object p1, p0, Llyiahf/vczjk/yz3;->OooOOOO:Ljava/lang/reflect/Constructor;

    if-eqz p1, :cond_1

    return-void

    :cond_1
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string p2, "Missing constructor (broken JDK (de)serialization?)"

    invoke-direct {p1, p2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/yz3;->OooOOOO:Ljava/lang/reflect/Constructor;

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->OooOo()Llyiahf/vczjk/gc4;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    if-ne v1, v2, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/e94;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    goto :goto_0

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/ph8;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    if-eqz v1, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v0, p1, p2, v1}, Llyiahf/vczjk/e94;->OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;

    move-result-object p1

    goto :goto_0

    :cond_1
    :try_start_0
    filled-new-array {p3}, [Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    iget-object v1, p0, Llyiahf/vczjk/ph8;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v1, p1, p2, v0}, Llyiahf/vczjk/e94;->OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;

    move-object p1, v0

    :goto_0
    invoke-virtual {p0, p3, p1}, Llyiahf/vczjk/oh8;->OooOoO0(Ljava/lang/Object;Ljava/lang/Object;)V

    return-void

    :catch_0
    move-exception p1

    invoke-virtual {v0}, Ljava/lang/reflect/Constructor;->getDeclaringClass()Ljava/lang/Class;

    move-result-object p2

    invoke-virtual {p2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object p3

    const-string v0, "Failed to instantiate class "

    const-string v1, ", problem: "

    invoke-static {v0, p2, v1, p3}, Llyiahf/vczjk/ii5;->OooO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOOOO(Ljava/lang/Exception;)Ljava/lang/Throwable;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOoO(Ljava/lang/Throwable;)V

    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOo(Ljava/lang/Throwable;)V

    new-instance p3, Ljava/lang/IllegalArgumentException;

    invoke-direct {p3, p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw p3
.end method

.method public final OooOO0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/ph8;->OooO0oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {p0, p3, p1}, Llyiahf/vczjk/oh8;->OooOoO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final Oooo00O(Llyiahf/vczjk/ph8;)Llyiahf/vczjk/ph8;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/oh8;->delegate:Llyiahf/vczjk/ph8;

    if-ne p1, v0, :cond_0

    return-object p0

    :cond_0
    new-instance v0, Llyiahf/vczjk/yz3;

    iget-object v1, p0, Llyiahf/vczjk/yz3;->OooOOOO:Ljava/lang/reflect/Constructor;

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/yz3;-><init>(Llyiahf/vczjk/ph8;Ljava/lang/reflect/Constructor;)V

    return-object v0
.end method

.method public readResolve()Ljava/lang/Object;
    .locals 2

    new-instance v0, Llyiahf/vczjk/yz3;

    iget-object v1, p0, Llyiahf/vczjk/yz3;->_annotated:Llyiahf/vczjk/jm;

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/yz3;-><init>(Llyiahf/vczjk/yz3;Llyiahf/vczjk/jm;)V

    return-object v0
.end method

.method public writeReplace()Ljava/lang/Object;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/yz3;->_annotated:Llyiahf/vczjk/jm;

    if-nez v0, :cond_0

    new-instance v0, Llyiahf/vczjk/yz3;

    new-instance v1, Llyiahf/vczjk/jm;

    iget-object v2, p0, Llyiahf/vczjk/yz3;->OooOOOO:Ljava/lang/reflect/Constructor;

    const/4 v3, 0x0

    invoke-direct {v1, v3, v2, v3, v3}, Llyiahf/vczjk/jm;-><init>(Llyiahf/vczjk/a5a;Ljava/lang/reflect/Constructor;Llyiahf/vczjk/ao;[Llyiahf/vczjk/ao;)V

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/yz3;-><init>(Llyiahf/vczjk/yz3;Llyiahf/vczjk/jm;)V

    return-object v0

    :cond_0
    return-object p0
.end method
