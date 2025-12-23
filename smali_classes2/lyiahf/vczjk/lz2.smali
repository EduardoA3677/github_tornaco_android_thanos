.class public final Llyiahf/vczjk/lz2;
.super Llyiahf/vczjk/iz2;
.source "SourceFile"


# instance fields
.field public OooO0O0:Z

.field public OooO0OO:[Ljava/io/File;

.field public OooO0Oo:I

.field public final synthetic OooO0o0:Llyiahf/vczjk/mz2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/mz2;Ljava/io/File;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/lz2;->OooO0o0:Llyiahf/vczjk/mz2;

    invoke-direct {p0, p2}, Llyiahf/vczjk/nz2;-><init>(Ljava/io/File;)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/io/File;
    .locals 6

    iget-boolean v0, p0, Llyiahf/vczjk/lz2;->OooO0O0:Z

    iget-object v1, p0, Llyiahf/vczjk/nz2;->OooO00o:Ljava/io/File;

    iget-object v2, p0, Llyiahf/vczjk/lz2;->OooO0o0:Llyiahf/vczjk/mz2;

    if-nez v0, :cond_0

    iget-object v0, v2, Llyiahf/vczjk/mz2;->OooOOOo:Llyiahf/vczjk/oz2;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/lz2;->OooO0O0:Z

    return-object v1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/lz2;->OooO0OO:[Ljava/io/File;

    const/4 v3, 0x0

    if-eqz v0, :cond_2

    iget v4, p0, Llyiahf/vczjk/lz2;->OooO0Oo:I

    array-length v5, v0

    if-ge v4, v5, :cond_1

    goto :goto_0

    :cond_1
    iget-object v0, v2, Llyiahf/vczjk/mz2;->OooOOOo:Llyiahf/vczjk/oz2;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    return-object v3

    :cond_2
    :goto_0
    if-nez v0, :cond_5

    invoke-virtual {v1}, Ljava/io/File;->listFiles()[Ljava/io/File;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/lz2;->OooO0OO:[Ljava/io/File;

    if-nez v0, :cond_3

    iget-object v0, v2, Llyiahf/vczjk/mz2;->OooOOOo:Llyiahf/vczjk/oz2;

    iget-object v0, v0, Llyiahf/vczjk/oz2;->OooO0Oo:Llyiahf/vczjk/cf3;

    check-cast v0, Llyiahf/vczjk/uu;

    if-eqz v0, :cond_3

    new-instance v4, Llyiahf/vczjk/o0O00;

    const-string v5, "Cannot list files in a directory"

    invoke-direct {v4, v1, v3, v5}, Llyiahf/vczjk/fz2;-><init>(Ljava/io/File;Ljava/io/File;Ljava/lang/String;)V

    invoke-virtual {v0, v1, v4}, Llyiahf/vczjk/uu;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_3
    iget-object v0, p0, Llyiahf/vczjk/lz2;->OooO0OO:[Ljava/io/File;

    if-eqz v0, :cond_4

    array-length v0, v0

    if-nez v0, :cond_5

    :cond_4
    iget-object v0, v2, Llyiahf/vczjk/mz2;->OooOOOo:Llyiahf/vczjk/oz2;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    return-object v3

    :cond_5
    iget-object v0, p0, Llyiahf/vczjk/lz2;->OooO0OO:[Ljava/io/File;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget v1, p0, Llyiahf/vczjk/lz2;->OooO0Oo:I

    add-int/lit8 v2, v1, 0x1

    iput v2, p0, Llyiahf/vczjk/lz2;->OooO0Oo:I

    aget-object v0, v0, v1

    return-object v0
.end method
