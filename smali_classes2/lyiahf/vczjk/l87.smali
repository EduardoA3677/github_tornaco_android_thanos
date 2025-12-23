.class public abstract Llyiahf/vczjk/l87;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static OooO00o:Z

.field public static final OooO0O0:Llyiahf/vczjk/era;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    const/4 v0, 0x1

    new-instance v1, Llyiahf/vczjk/rf;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    new-instance v2, Llyiahf/vczjk/lr;

    new-instance v3, Ljava/io/File;

    invoke-static {}, Llyiahf/vczjk/rd3;->OooOO0O()Ljava/io/File;

    move-result-object v4

    const-string v5, "log"

    invoke-direct {v3, v4, v5}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-virtual {v3}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object v3

    invoke-direct {v2, v3}, Llyiahf/vczjk/lr;-><init>(Ljava/lang/String;)V

    new-instance v3, Llyiahf/vczjk/q93;

    const-string v4, "profile.log"

    invoke-direct {v3, v4, v0}, Llyiahf/vczjk/q93;-><init>(Ljava/lang/String;I)V

    iput-object v3, v2, Llyiahf/vczjk/lr;->OooOOOo:Ljava/lang/Object;

    new-instance v3, Llyiahf/vczjk/e86;

    const/16 v4, 0x10

    invoke-direct {v3, v4}, Llyiahf/vczjk/e86;-><init>(I)V

    iput-object v3, v2, Llyiahf/vczjk/lr;->OooOOo:Ljava/lang/Object;

    new-instance v3, Llyiahf/vczjk/dz0;

    invoke-direct {v3}, Llyiahf/vczjk/dz0;-><init>()V

    iput-object v3, v2, Llyiahf/vczjk/lr;->OooOOoo:Ljava/lang/Object;

    invoke-virtual {v2}, Llyiahf/vczjk/lr;->OooO0oo()Llyiahf/vczjk/zy2;

    move-result-object v2

    invoke-static {}, Llyiahf/vczjk/zsa;->OooOoo0()V

    const/4 v3, 0x2

    new-array v3, v3, [Llyiahf/vczjk/r47;

    const/4 v4, 0x0

    aput-object v1, v3, v4

    aput-object v2, v3, v0

    new-instance v0, Llyiahf/vczjk/cj1;

    invoke-direct {v0, v3}, Llyiahf/vczjk/cj1;-><init>([Llyiahf/vczjk/r47;)V

    new-instance v1, Llyiahf/vczjk/era;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    new-instance v2, Llyiahf/vczjk/f55;

    sget-object v3, Llyiahf/vczjk/zsa;->OooO0O0:Llyiahf/vczjk/f55;

    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    const/high16 v4, -0x80000000

    iput v4, v2, Llyiahf/vczjk/f55;->OooO00o:I

    const-string v5, "ThanoxLog"

    iput-object v5, v2, Llyiahf/vczjk/f55;->OooO0O0:Ljava/lang/String;

    iget v5, v3, Llyiahf/vczjk/f55;->OooO00o:I

    iput v5, v2, Llyiahf/vczjk/f55;->OooO00o:I

    iget-object v5, v3, Llyiahf/vczjk/f55;->OooO0O0:Ljava/lang/String;

    iput-object v5, v2, Llyiahf/vczjk/f55;->OooO0O0:Ljava/lang/String;

    iget-boolean v5, v3, Llyiahf/vczjk/f55;->OooO0OO:Z

    iput-boolean v5, v2, Llyiahf/vczjk/f55;->OooO0OO:Z

    iget-boolean v5, v3, Llyiahf/vczjk/f55;->OooO0Oo:Z

    iput-boolean v5, v2, Llyiahf/vczjk/f55;->OooO0Oo:Z

    iget-boolean v5, v3, Llyiahf/vczjk/f55;->OooO0o0:Z

    iput-boolean v5, v2, Llyiahf/vczjk/f55;->OooO0o0:Z

    iget-object v5, v3, Llyiahf/vczjk/f55;->OooO0o:Llyiahf/vczjk/e86;

    iput-object v5, v2, Llyiahf/vczjk/f55;->OooO0o:Llyiahf/vczjk/e86;

    iget-object v5, v3, Llyiahf/vczjk/f55;->OooO0oO:Llyiahf/vczjk/qp3;

    iput-object v5, v2, Llyiahf/vczjk/f55;->OooO0oO:Llyiahf/vczjk/qp3;

    iget-object v5, v3, Llyiahf/vczjk/f55;->OooO0oo:Llyiahf/vczjk/pp3;

    iput-object v5, v2, Llyiahf/vczjk/f55;->OooO0oo:Llyiahf/vczjk/pp3;

    iget-object v5, v3, Llyiahf/vczjk/f55;->OooO:Llyiahf/vczjk/op3;

    iput-object v5, v2, Llyiahf/vczjk/f55;->OooO:Llyiahf/vczjk/op3;

    iget-object v5, v3, Llyiahf/vczjk/f55;->OooOO0:Llyiahf/vczjk/uk2;

    iput-object v5, v2, Llyiahf/vczjk/f55;->OooOO0:Llyiahf/vczjk/uk2;

    iget-object v5, v3, Llyiahf/vczjk/f55;->OooOO0O:Llyiahf/vczjk/up3;

    iput-object v5, v2, Llyiahf/vczjk/f55;->OooOO0O:Llyiahf/vczjk/up3;

    iget-object v5, v3, Llyiahf/vczjk/f55;->OooOO0o:Ljava/util/HashMap;

    if-eqz v5, :cond_0

    new-instance v6, Ljava/util/HashMap;

    invoke-direct {v6, v5}, Ljava/util/HashMap;-><init>(Ljava/util/Map;)V

    iput-object v6, v2, Llyiahf/vczjk/f55;->OooOO0o:Ljava/util/HashMap;

    :cond_0
    iget-object v3, v3, Llyiahf/vczjk/f55;->OooOOO0:Ljava/util/ArrayList;

    if-eqz v3, :cond_1

    new-instance v5, Ljava/util/ArrayList;

    invoke-direct {v5, v3}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v5, v2, Llyiahf/vczjk/f55;->OooOOO0:Ljava/util/ArrayList;

    :cond_1
    iput v4, v2, Llyiahf/vczjk/f55;->OooO00o:I

    const-string v3, "[Profile]"

    iput-object v3, v2, Llyiahf/vczjk/f55;->OooO0O0:Ljava/lang/String;

    invoke-virtual {v2}, Llyiahf/vczjk/f55;->OooO00o()Llyiahf/vczjk/f55;

    move-result-object v2

    iput-object v2, v1, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    iput-object v0, v1, Llyiahf/vczjk/era;->OooOOO:Ljava/lang/Object;

    sput-object v1, Llyiahf/vczjk/l87;->OooO0O0:Llyiahf/vczjk/era;

    return-void
.end method

.method public static OooO00o()Ljava/io/File;
    .locals 4

    new-instance v0, Ljava/io/File;

    new-instance v1, Ljava/io/File;

    invoke-static {}, Llyiahf/vczjk/rd3;->OooOO0O()Ljava/io/File;

    move-result-object v2

    const-string v3, "log"

    invoke-direct {v1, v2, v3}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    const-string v2, "profile.log"

    invoke-direct {v0, v1, v2}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    return-object v0
.end method

.method public static final OooO0O0(Ljava/lang/String;)V
    .locals 2

    const-string v0, "message"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-boolean v0, Llyiahf/vczjk/l87;->OooO00o:Z

    if-eqz v0, :cond_0

    const/4 v0, 0x5

    sget-object v1, Llyiahf/vczjk/l87;->OooO0O0:Llyiahf/vczjk/era;

    invoke-virtual {v1, v0, p0}, Llyiahf/vczjk/era;->OoooO(ILjava/lang/String;)V

    :cond_0
    return-void
.end method

.method public static final OooO0OO(Ljava/lang/String;Ljava/lang/Throwable;)V
    .locals 2

    const-string v0, "message"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-boolean v0, Llyiahf/vczjk/l87;->OooO00o:Z

    if-eqz v0, :cond_0

    const/4 v0, 0x6

    sget-object v1, Llyiahf/vczjk/l87;->OooO0O0:Llyiahf/vczjk/era;

    invoke-virtual {v1, v0, p0, p1}, Llyiahf/vczjk/era;->OoooOO0(ILjava/lang/String;Ljava/lang/Throwable;)V

    :cond_0
    return-void
.end method

.method public static final varargs OooO0Oo(Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 2

    sget-boolean v0, Llyiahf/vczjk/l87;->OooO00o:Z

    if-eqz v0, :cond_0

    :try_start_0
    sget-object v0, Llyiahf/vczjk/l87;->OooO0O0:Llyiahf/vczjk/era;

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    const/4 v1, 0x1

    invoke-static {p1, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p1

    invoke-static {p0, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    const/4 p1, 0x5

    invoke-virtual {v0, p1, p0}, Llyiahf/vczjk/era;->OoooO(ILjava/lang/String;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-void

    :catchall_0
    move-exception p0

    invoke-static {p0}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    :cond_0
    return-void
.end method
