.class public abstract Llyiahf/vczjk/ul1;
.super Llyiahf/vczjk/m49;
.source "SourceFile"


# instance fields
.field protected final _containerType:Llyiahf/vczjk/x64;

.field protected final _nullProvider:Llyiahf/vczjk/u46;

.field protected final _skipNullValues:Z

.field protected final _unwrapSingle:Ljava/lang/Boolean;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ul1;Llyiahf/vczjk/u46;Ljava/lang/Boolean;)V
    .locals 1

    iget-object v0, p1, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    invoke-direct {p0, v0}, Llyiahf/vczjk/m49;-><init>(Llyiahf/vczjk/x64;)V

    iget-object p1, p1, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    iput-object p1, p0, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    iput-object p2, p0, Llyiahf/vczjk/ul1;->_nullProvider:Llyiahf/vczjk/u46;

    iput-object p3, p0, Llyiahf/vczjk/ul1;->_unwrapSingle:Ljava/lang/Boolean;

    invoke-static {p2}, Llyiahf/vczjk/f56;->OooO00o(Llyiahf/vczjk/u46;)Z

    move-result p1

    iput-boolean p1, p0, Llyiahf/vczjk/ul1;->_skipNullValues:Z

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/u46;Ljava/lang/Boolean;)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/m49;-><init>(Llyiahf/vczjk/x64;)V

    iput-object p1, p0, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    iput-object p3, p0, Llyiahf/vczjk/ul1;->_unwrapSingle:Ljava/lang/Boolean;

    iput-object p2, p0, Llyiahf/vczjk/ul1;->_nullProvider:Llyiahf/vczjk/u46;

    invoke-static {p2}, Llyiahf/vczjk/f56;->OooO00o(Llyiahf/vczjk/u46;)Z

    move-result p1

    iput-boolean p1, p0, Llyiahf/vczjk/ul1;->_skipNullValues:Z

    return-void
.end method

.method public static OoooOo0(Ljava/lang/Exception;Ljava/lang/Object;Ljava/lang/String;)V
    .locals 1

    :goto_0
    instance-of v0, p0, Ljava/lang/reflect/InvocationTargetException;

    if-eqz v0, :cond_0

    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    move-result-object p0

    goto :goto_0

    :cond_0
    invoke-static {p0}, Llyiahf/vczjk/vy0;->OooOo(Ljava/lang/Throwable;)V

    instance-of v0, p0, Ljava/io/IOException;

    if-eqz v0, :cond_2

    instance-of v0, p0, Llyiahf/vczjk/na4;

    if-eqz v0, :cond_1

    goto :goto_1

    :cond_1
    check-cast p0, Ljava/io/IOException;

    throw p0

    :cond_2
    :goto_1
    if-nez p2, :cond_3

    const-string p2, "N/A"

    :cond_3
    sget v0, Llyiahf/vczjk/na4;->OooOOO:I

    new-instance v0, Llyiahf/vczjk/ma4;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/ma4;-><init>(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0, v0}, Llyiahf/vczjk/na4;->OooO0oo(Ljava/lang/Throwable;Llyiahf/vczjk/ma4;)Llyiahf/vczjk/na4;

    move-result-object p0

    throw p0
.end method


# virtual methods
.method public OooO()Llyiahf/vczjk/o0OoO00O;
    .locals 1

    sget-object v0, Llyiahf/vczjk/o0OoO00O;->OooOOOO:Llyiahf/vczjk/o0OoO00O;

    return-object v0
.end method

.method public final OooO0oo(Ljava/lang/String;)Llyiahf/vczjk/ph8;
    .locals 5

    invoke-virtual {p0}, Llyiahf/vczjk/ul1;->OoooOOO()Llyiahf/vczjk/e94;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/e94;->OooO0oo(Ljava/lang/String;)Llyiahf/vczjk/ph8;

    move-result-object p1

    return-object p1

    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    const-string v2, "Cannot handle managed/back reference \'"

    const-string v3, "\': type: container deserializer of type "

    const-string v4, " returned null for \'getContentDeserializer()\'"

    invoke-static {v2, p1, v3, v1, v4}, Llyiahf/vczjk/ii5;->OooOO0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public OooOO0(Llyiahf/vczjk/v72;)Ljava/lang/Object;
    .locals 4

    invoke-virtual {p0}, Llyiahf/vczjk/ul1;->OoooOOo()Llyiahf/vczjk/nca;

    move-result-object v0

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/nca;->OooO()Z

    move-result v2

    if-eqz v2, :cond_0

    :try_start_0
    invoke-virtual {v0, p1}, Llyiahf/vczjk/nca;->OooOOoo(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    return-object p1

    :catch_0
    move-exception v0

    invoke-static {p1, v0}, Llyiahf/vczjk/vy0;->OooOo0o(Llyiahf/vczjk/v72;Ljava/io/IOException;)V

    throw v1

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/ul1;->OoooO()Llyiahf/vczjk/x64;

    move-result-object v0

    const-string v2, "Cannot create empty instance of %s, no default Creator"

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v3

    invoke-static {v2, v3}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p1, v0, v2}, Llyiahf/vczjk/v72;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    throw v1
.end method

.method public final OooOOOO(Llyiahf/vczjk/t72;)Ljava/lang/Boolean;
    .locals 0

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1
.end method

.method public OoooO()Llyiahf/vczjk/x64;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    return-object v0
.end method

.method public abstract OoooOOO()Llyiahf/vczjk/e94;
.end method

.method public OoooOOo()Llyiahf/vczjk/nca;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method
