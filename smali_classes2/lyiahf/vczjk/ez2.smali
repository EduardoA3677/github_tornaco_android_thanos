.class public abstract Llyiahf/vczjk/ez2;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/we4;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    :try_start_0
    const-string v0, "java.nio.file.Files"

    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    new-instance v0, Llyiahf/vczjk/d16;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V
    :try_end_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    new-instance v0, Llyiahf/vczjk/we4;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    :goto_0
    sput-object v0, Llyiahf/vczjk/ez2;->OooO00o:Llyiahf/vczjk/we4;

    sget-object v0, Llyiahf/vczjk/zp6;->OooOOO:Ljava/lang/String;

    const-string v0, "java.io.tmpdir"

    invoke-static {v0}, Ljava/lang/System;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    const-string v1, "getProperty(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v1, 0x0

    invoke-static {v0, v1}, Llyiahf/vczjk/xj0;->OooOOOo(Ljava/lang/String;Z)Llyiahf/vczjk/zp6;

    new-instance v0, Llyiahf/vczjk/vr7;

    const-class v1, Llyiahf/vczjk/vr7;

    invoke-virtual {v1}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    move-result-object v1

    const-string v2, "getClassLoader(...)"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {v0, v1}, Llyiahf/vczjk/vr7;-><init>(Ljava/lang/ClassLoader;)V

    return-void
.end method


# virtual methods
.method public abstract OooO(Llyiahf/vczjk/zp6;)Llyiahf/vczjk/sd4;
.end method

.method public final OooO00o(Llyiahf/vczjk/zp6;)V
    .locals 2

    new-instance v0, Llyiahf/vczjk/xx;

    invoke-direct {v0}, Llyiahf/vczjk/xx;-><init>()V

    :goto_0
    if-eqz p1, :cond_0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ez2;->OooO0o0(Llyiahf/vczjk/zp6;)Z

    move-result v1

    if-nez v1, :cond_0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/xx;->addFirst(Ljava/lang/Object;)V

    invoke-virtual {p1}, Llyiahf/vczjk/zp6;->OooO0OO()Llyiahf/vczjk/zp6;

    move-result-object p1

    goto :goto_0

    :cond_0
    invoke-virtual {v0}, Ljava/util/AbstractCollection;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/zp6;

    const-string v1, "dir"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0, v0}, Llyiahf/vczjk/ez2;->OooO0O0(Llyiahf/vczjk/zp6;)V

    goto :goto_1

    :cond_1
    return-void
.end method

.method public abstract OooO0O0(Llyiahf/vczjk/zp6;)V
.end method

.method public abstract OooO0OO(Llyiahf/vczjk/zp6;)V
.end method

.method public final OooO0Oo(Llyiahf/vczjk/zp6;)V
    .locals 1

    const-string v0, "path"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ez2;->OooO0OO(Llyiahf/vczjk/zp6;)V

    return-void
.end method

.method public abstract OooO0o(Llyiahf/vczjk/zp6;)Ljava/util/List;
.end method

.method public final OooO0o0(Llyiahf/vczjk/zp6;)Z
    .locals 1

    const-string v0, "path"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ez2;->OooO0oo(Llyiahf/vczjk/zp6;)Llyiahf/vczjk/o62;

    move-result-object p1

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final OooO0oO(Llyiahf/vczjk/zp6;)Llyiahf/vczjk/o62;
    .locals 3

    const-string v0, "path"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ez2;->OooO0oo(Llyiahf/vczjk/zp6;)Llyiahf/vczjk/o62;

    move-result-object v0

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    new-instance v0, Ljava/io/FileNotFoundException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "no such file: "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/io/FileNotFoundException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public abstract OooO0oo(Llyiahf/vczjk/zp6;)Llyiahf/vczjk/o62;
.end method

.method public abstract OooOO0(Llyiahf/vczjk/zp6;)Llyiahf/vczjk/rq8;
.end method

.method public abstract OooOO0O(Llyiahf/vczjk/zp6;)Llyiahf/vczjk/rx8;
.end method
