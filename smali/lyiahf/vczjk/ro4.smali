.class public final Llyiahf/vczjk/ro4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ce1;
.implements Llyiahf/vczjk/ug6;
.implements Llyiahf/vczjk/bo4;
.implements Llyiahf/vczjk/ke8;
.implements Llyiahf/vczjk/af1;


# static fields
.field public static final Ooooo0o:Llyiahf/vczjk/bv7;

.field public static final OooooO0:Llyiahf/vczjk/ko4;

.field public static final OooooOO:Llyiahf/vczjk/qw;


# instance fields
.field public OooOOO:I

.field public final OooOOO0:Z

.field public OooOOOO:J

.field public OooOOOo:J

.field public OooOOo:Z

.field public OooOOo0:J

.field public OooOOoo:Z

.field public OooOo:Z

.field public OooOo0:I

.field public OooOo00:Llyiahf/vczjk/ro4;

.field public final OooOo0O:Llyiahf/vczjk/era;

.field public OooOo0o:Llyiahf/vczjk/ws5;

.field public OooOoO:Llyiahf/vczjk/xa;

.field public OooOoO0:Llyiahf/vczjk/ro4;

.field public OooOoOO:Llyiahf/vczjk/nga;

.field public OooOoo:Z

.field public OooOoo0:I

.field public OooOooO:Z

.field public OooOooo:Llyiahf/vczjk/je8;

.field public Oooo:Llyiahf/vczjk/no4;

.field public Oooo0:Llyiahf/vczjk/lf5;

.field public Oooo000:Z

.field public final Oooo00O:Llyiahf/vczjk/ws5;

.field public Oooo00o:Z

.field public Oooo0O0:Llyiahf/vczjk/era;

.field public Oooo0OO:Llyiahf/vczjk/f62;

.field public Oooo0o:Llyiahf/vczjk/gga;

.field public Oooo0o0:Llyiahf/vczjk/yn4;

.field public Oooo0oO:Llyiahf/vczjk/yg1;

.field public Oooo0oo:Llyiahf/vczjk/no4;

.field public OoooO:Llyiahf/vczjk/fp4;

.field public final OoooO0:Llyiahf/vczjk/jb0;

.field public OoooO00:Z

.field public final OoooO0O:Llyiahf/vczjk/vo4;

.field public OoooOO0:Llyiahf/vczjk/v16;

.field public OoooOOO:Llyiahf/vczjk/kl5;

.field public OoooOOo:Llyiahf/vczjk/kl5;

.field public OoooOo0:Llyiahf/vczjk/dh;

.field public OoooOoO:Llyiahf/vczjk/eh;

.field public OoooOoo:Z

.field public Ooooo00:Z

.field public o000oOoO:Z


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/bv7;

    const-string v1, "Undefined intrinsics block and it is required"

    const/4 v2, 0x1

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/bv7;-><init>(Ljava/lang/String;I)V

    sput-object v0, Llyiahf/vczjk/ro4;->Ooooo0o:Llyiahf/vczjk/bv7;

    new-instance v0, Llyiahf/vczjk/ko4;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/ro4;->OooooO0:Llyiahf/vczjk/ko4;

    new-instance v0, Llyiahf/vczjk/qw;

    const/4 v1, 0x7

    invoke-direct {v0, v1}, Llyiahf/vczjk/qw;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/ro4;->OooooOO:Llyiahf/vczjk/qw;

    return-void
.end method

.method public constructor <init>(I)V
    .locals 2

    const/4 v0, 0x1

    and-int/2addr p1, v0

    if-eqz p1, :cond_0

    const/4 p1, 0x0

    goto :goto_0

    :cond_0
    move p1, v0

    :goto_0
    sget-object v1, Llyiahf/vczjk/me8;->OooO00o:Ljava/util/concurrent/atomic/AtomicInteger;

    invoke-virtual {v1, v0}, Ljava/util/concurrent/atomic/AtomicInteger;->addAndGet(I)I

    move-result v0

    invoke-direct {p0, p1, v0}, Llyiahf/vczjk/ro4;-><init>(ZI)V

    return-void
.end method

.method public constructor <init>(ZI)V
    .locals 3

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Llyiahf/vczjk/ro4;->OooOOO0:Z

    iput p2, p0, Llyiahf/vczjk/ro4;->OooOOO:I

    const-wide p1, 0x7fffffff7fffffffL

    iput-wide p1, p0, Llyiahf/vczjk/ro4;->OooOOOO:J

    const-wide/16 v0, 0x0

    iput-wide v0, p0, Llyiahf/vczjk/ro4;->OooOOOo:J

    iput-wide p1, p0, Llyiahf/vczjk/ro4;->OooOOo0:J

    const/4 p1, 0x1

    iput-boolean p1, p0, Llyiahf/vczjk/ro4;->OooOOo:Z

    new-instance p2, Llyiahf/vczjk/era;

    new-instance v0, Llyiahf/vczjk/ws5;

    const/16 v1, 0x10

    new-array v2, v1, [Llyiahf/vczjk/ro4;

    invoke-direct {v0, v2}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    new-instance v2, Llyiahf/vczjk/po4;

    invoke-direct {v2, p0}, Llyiahf/vczjk/po4;-><init>(Llyiahf/vczjk/ro4;)V

    invoke-direct {p2, v0, v2}, Llyiahf/vczjk/era;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    iput-object p2, p0, Llyiahf/vczjk/ro4;->OooOo0O:Llyiahf/vczjk/era;

    new-instance p2, Llyiahf/vczjk/ws5;

    new-array v0, v1, [Llyiahf/vczjk/ro4;

    invoke-direct {p2, v0}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    iput-object p2, p0, Llyiahf/vczjk/ro4;->Oooo00O:Llyiahf/vczjk/ws5;

    iput-boolean p1, p0, Llyiahf/vczjk/ro4;->Oooo00o:Z

    sget-object p2, Llyiahf/vczjk/ro4;->Ooooo0o:Llyiahf/vczjk/bv7;

    iput-object p2, p0, Llyiahf/vczjk/ro4;->Oooo0:Llyiahf/vczjk/lf5;

    sget-object p2, Llyiahf/vczjk/uo4;->OooO00o:Llyiahf/vczjk/i62;

    iput-object p2, p0, Llyiahf/vczjk/ro4;->Oooo0OO:Llyiahf/vczjk/f62;

    sget-object p2, Llyiahf/vczjk/yn4;->OooOOO0:Llyiahf/vczjk/yn4;

    iput-object p2, p0, Llyiahf/vczjk/ro4;->Oooo0o0:Llyiahf/vczjk/yn4;

    sget-object p2, Llyiahf/vczjk/ro4;->OooooO0:Llyiahf/vczjk/ko4;

    iput-object p2, p0, Llyiahf/vczjk/ro4;->Oooo0o:Llyiahf/vczjk/gga;

    sget-object p2, Llyiahf/vczjk/yg1;->OooO0o0:Llyiahf/vczjk/xg1;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object p2, Llyiahf/vczjk/xg1;->OooO0O0:Llyiahf/vczjk/os6;

    iput-object p2, p0, Llyiahf/vczjk/ro4;->Oooo0oO:Llyiahf/vczjk/yg1;

    sget-object p2, Llyiahf/vczjk/no4;->OooOOOO:Llyiahf/vczjk/no4;

    iput-object p2, p0, Llyiahf/vczjk/ro4;->Oooo0oo:Llyiahf/vczjk/no4;

    iput-object p2, p0, Llyiahf/vczjk/ro4;->Oooo:Llyiahf/vczjk/no4;

    new-instance p2, Llyiahf/vczjk/jb0;

    invoke-direct {p2, p0}, Llyiahf/vczjk/jb0;-><init>(Llyiahf/vczjk/ro4;)V

    iput-object p2, p0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    new-instance p2, Llyiahf/vczjk/vo4;

    invoke-direct {p2, p0}, Llyiahf/vczjk/vo4;-><init>(Llyiahf/vczjk/ro4;)V

    iput-object p2, p0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iput-boolean p1, p0, Llyiahf/vczjk/ro4;->o000oOoO:Z

    sget-object p1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    iput-object p1, p0, Llyiahf/vczjk/ro4;->OoooOOO:Llyiahf/vczjk/kl5;

    return-void
.end method

.method private final OooOO0O(Llyiahf/vczjk/ro4;)Ljava/lang/String;
    .locals 3

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Cannot insert "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, " because it already has a parent or an owner. This tree: "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/4 v1, 0x0

    invoke-virtual {p0, v1}, Llyiahf/vczjk/ro4;->OooO0oO(I)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, " Other tree: "

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object p1, p1, Llyiahf/vczjk/ro4;->OooOoO0:Llyiahf/vczjk/ro4;

    if-eqz p1, :cond_0

    invoke-virtual {p1, v1}, Llyiahf/vczjk/ro4;->OooO0oO(I)Ljava/lang/String;

    move-result-object p1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

.method public static Oooo(Llyiahf/vczjk/ro4;)Z
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    iget-boolean v1, v0, Llyiahf/vczjk/kf5;->OooOo0O:Z

    if-eqz v1, :cond_0

    iget-wide v0, v0, Llyiahf/vczjk/ow6;->OooOOOo:J

    new-instance v2, Llyiahf/vczjk/rk1;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/rk1;-><init>(J)V

    goto :goto_0

    :cond_0
    const/4 v2, 0x0

    :goto_0
    invoke-virtual {p0, v2}, Llyiahf/vczjk/ro4;->Oooo0oo(Llyiahf/vczjk/rk1;)Z

    move-result p0

    return p0
.end method

.method public static OoooOO0(Llyiahf/vczjk/ro4;ZI)V
    .locals 4

    and-int/lit8 v0, p2, 0x1

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    move p1, v1

    :cond_0
    and-int/lit8 v0, p2, 0x2

    const/4 v2, 0x1

    if-eqz v0, :cond_1

    move v0, v2

    goto :goto_0

    :cond_1
    move v0, v1

    :goto_0
    and-int/lit8 p2, p2, 0x4

    if-eqz p2, :cond_2

    move v1, v2

    :cond_2
    iget-object p2, p0, Llyiahf/vczjk/ro4;->OooOo00:Llyiahf/vczjk/ro4;

    if-eqz p2, :cond_3

    goto :goto_1

    :cond_3
    const-string p2, "Lookahead measure cannot be requested on a node that is not a part of theLookaheadScope"

    invoke-static {p2}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :goto_1
    iget-object p2, p0, Llyiahf/vczjk/ro4;->OooOoO:Llyiahf/vczjk/xa;

    if-nez p2, :cond_4

    goto :goto_4

    :cond_4
    iget-boolean v3, p0, Llyiahf/vczjk/ro4;->OooOoo:Z

    if-nez v3, :cond_b

    iget-boolean v3, p0, Llyiahf/vczjk/ro4;->OooOOO0:Z

    if-nez v3, :cond_b

    invoke-virtual {p2, p0, v2, p1, v0}, Llyiahf/vczjk/xa;->OooOoo0(Llyiahf/vczjk/ro4;ZZZ)V

    if-eqz v1, :cond_b

    iget-object p0, p0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object p0, p0, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    invoke-static {p0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object p0, p0, Llyiahf/vczjk/w65;->OooOOo:Llyiahf/vczjk/vo4;

    iget-object p2, p0, Llyiahf/vczjk/vo4;->OooO00o:Llyiahf/vczjk/ro4;

    invoke-virtual {p2}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object p2

    iget-object p0, p0, Llyiahf/vczjk/vo4;->OooO00o:Llyiahf/vczjk/ro4;

    iget-object p0, p0, Llyiahf/vczjk/ro4;->Oooo0oo:Llyiahf/vczjk/no4;

    if-eqz p2, :cond_b

    sget-object v0, Llyiahf/vczjk/no4;->OooOOOO:Llyiahf/vczjk/no4;

    if-eq p0, v0, :cond_b

    :goto_2
    iget-object v0, p2, Llyiahf/vczjk/ro4;->Oooo0oo:Llyiahf/vczjk/no4;

    if-ne v0, p0, :cond_6

    invoke-virtual {p2}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v0

    if-nez v0, :cond_5

    goto :goto_3

    :cond_5
    move-object p2, v0

    goto :goto_2

    :cond_6
    :goto_3
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    move-result p0

    if-eqz p0, :cond_9

    if-ne p0, v2, :cond_8

    iget-object p0, p2, Llyiahf/vczjk/ro4;->OooOo00:Llyiahf/vczjk/ro4;

    if-eqz p0, :cond_7

    invoke-virtual {p2, p1}, Llyiahf/vczjk/ro4;->OoooO(Z)V

    return-void

    :cond_7
    invoke-virtual {p2, p1}, Llyiahf/vczjk/ro4;->o000oOoO(Z)V

    return-void

    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "Intrinsics isn\'t used by the parent"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_9
    iget-object p0, p2, Llyiahf/vczjk/ro4;->OooOo00:Llyiahf/vczjk/ro4;

    const/4 v0, 0x6

    if-eqz p0, :cond_a

    invoke-static {p2, p1, v0}, Llyiahf/vczjk/ro4;->OoooOO0(Llyiahf/vczjk/ro4;ZI)V

    return-void

    :cond_a
    invoke-static {p2, p1, v0}, Llyiahf/vczjk/ro4;->OoooOOO(Llyiahf/vczjk/ro4;ZI)V

    :cond_b
    :goto_4
    return-void
.end method

.method public static OoooOOO(Llyiahf/vczjk/ro4;ZI)V
    .locals 4

    and-int/lit8 v0, p2, 0x1

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    move p1, v1

    :cond_0
    and-int/lit8 v0, p2, 0x2

    const/4 v2, 0x1

    if-eqz v0, :cond_1

    move v0, v2

    goto :goto_0

    :cond_1
    move v0, v1

    :goto_0
    and-int/lit8 p2, p2, 0x4

    if-eqz p2, :cond_2

    move p2, v2

    goto :goto_1

    :cond_2
    move p2, v1

    :goto_1
    iget-boolean v3, p0, Llyiahf/vczjk/ro4;->OooOoo:Z

    if-nez v3, :cond_8

    iget-boolean v3, p0, Llyiahf/vczjk/ro4;->OooOOO0:Z

    if-nez v3, :cond_8

    iget-object v3, p0, Llyiahf/vczjk/ro4;->OooOoO:Llyiahf/vczjk/xa;

    if-nez v3, :cond_3

    goto :goto_4

    :cond_3
    invoke-virtual {v3, p0, v1, p1, v0}, Llyiahf/vczjk/xa;->OooOoo0(Llyiahf/vczjk/ro4;ZZZ)V

    if-eqz p2, :cond_8

    iget-object p0, p0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object p0, p0, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    iget-object p0, p0, Llyiahf/vczjk/kf5;->OooOOo:Llyiahf/vczjk/vo4;

    iget-object p2, p0, Llyiahf/vczjk/vo4;->OooO00o:Llyiahf/vczjk/ro4;

    invoke-virtual {p2}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object p2

    iget-object p0, p0, Llyiahf/vczjk/vo4;->OooO00o:Llyiahf/vczjk/ro4;

    iget-object p0, p0, Llyiahf/vczjk/ro4;->Oooo0oo:Llyiahf/vczjk/no4;

    if-eqz p2, :cond_8

    sget-object v0, Llyiahf/vczjk/no4;->OooOOOO:Llyiahf/vczjk/no4;

    if-eq p0, v0, :cond_8

    :goto_2
    iget-object v0, p2, Llyiahf/vczjk/ro4;->Oooo0oo:Llyiahf/vczjk/no4;

    if-ne v0, p0, :cond_5

    invoke-virtual {p2}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v0

    if-nez v0, :cond_4

    goto :goto_3

    :cond_4
    move-object p2, v0

    goto :goto_2

    :cond_5
    :goto_3
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    move-result p0

    if-eqz p0, :cond_7

    if-ne p0, v2, :cond_6

    invoke-virtual {p2, p1}, Llyiahf/vczjk/ro4;->o000oOoO(Z)V

    return-void

    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "Intrinsics isn\'t used by the parent"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_7
    const/4 p0, 0x6

    invoke-static {p2, p1, p0}, Llyiahf/vczjk/ro4;->OoooOOO(Llyiahf/vczjk/ro4;ZI)V

    :cond_8
    :goto_4
    return-void
.end method

.method public static OoooOOo(Llyiahf/vczjk/ro4;)V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooO0Oo:Llyiahf/vczjk/lo4;

    sget-object v1, Llyiahf/vczjk/oo4;->OooO00o:[I

    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    aget v0, v1, v0

    const/4 v1, 0x1

    iget-object v2, p0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    if-ne v0, v1, :cond_4

    iget-boolean v0, v2, Llyiahf/vczjk/vo4;->OooO0o0:Z

    const/4 v3, 0x6

    if-eqz v0, :cond_0

    invoke-static {p0, v1, v3}, Llyiahf/vczjk/ro4;->OoooOO0(Llyiahf/vczjk/ro4;ZI)V

    return-void

    :cond_0
    iget-boolean v0, v2, Llyiahf/vczjk/vo4;->OooO0o:Z

    if-eqz v0, :cond_1

    invoke-virtual {p0, v1}, Llyiahf/vczjk/ro4;->OoooO(Z)V

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooOOoo()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-static {p0, v1, v3}, Llyiahf/vczjk/ro4;->OoooOOO(Llyiahf/vczjk/ro4;ZI)V

    return-void

    :cond_2
    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooOOo()Z

    move-result v0

    if-eqz v0, :cond_3

    invoke-virtual {p0, v1}, Llyiahf/vczjk/ro4;->o000oOoO(Z)V

    :cond_3
    return-void

    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Unexpected state "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, v2, Llyiahf/vczjk/vo4;->OooO0Oo:Llyiahf/vczjk/lo4;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method


# virtual methods
.method public final OooO()V
    .locals 8

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->Oooo00o()Z

    move-result v0

    if-nez v0, :cond_0

    const-string v0, "onReuse is only expected on attached node"

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO00o(Ljava/lang/String;)V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/ro4;->OooOoOO:Llyiahf/vczjk/nga;

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/nh;->OooO()V

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO:Llyiahf/vczjk/fp4;

    const/4 v1, 0x0

    if-eqz v0, :cond_2

    invoke-virtual {v0, v1}, Llyiahf/vczjk/fp4;->OooO0o0(Z)V

    :cond_2
    iput-boolean v1, p0, Llyiahf/vczjk/ro4;->Oooo000:Z

    iget-boolean v0, p0, Llyiahf/vczjk/ro4;->Ooooo00:Z

    iget-object v2, p0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    if-eqz v0, :cond_3

    iput-boolean v1, p0, Llyiahf/vczjk/ro4;->Ooooo00:Z

    goto :goto_2

    :cond_3
    iget-object v0, v2, Llyiahf/vczjk/jb0;->OooO0o0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cf9;

    :goto_0
    if-eqz v0, :cond_5

    iget-boolean v3, v0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v3, :cond_4

    invoke-virtual {v0}, Llyiahf/vczjk/jl5;->o000000O()V

    :cond_4
    iget-object v0, v0, Llyiahf/vczjk/jl5;->OooOOo0:Llyiahf/vczjk/jl5;

    goto :goto_0

    :cond_5
    invoke-virtual {v2}, Llyiahf/vczjk/jb0;->OooO0oO()V

    iget-object v0, v2, Llyiahf/vczjk/jb0;->OooO0o0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cf9;

    :goto_1
    if-eqz v0, :cond_7

    iget-boolean v3, v0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v3, :cond_6

    invoke-virtual {v0}, Llyiahf/vczjk/jl5;->oo0o0Oo()V

    :cond_6
    iget-object v0, v0, Llyiahf/vczjk/jl5;->OooOOo0:Llyiahf/vczjk/jl5;

    goto :goto_1

    :cond_7
    :goto_2
    iget v0, p0, Llyiahf/vczjk/ro4;->OooOOO:I

    sget-object v3, Llyiahf/vczjk/me8;->OooO00o:Ljava/util/concurrent/atomic/AtomicInteger;

    const/4 v4, 0x1

    invoke-virtual {v3, v4}, Ljava/util/concurrent/atomic/AtomicInteger;->addAndGet(I)I

    move-result v3

    iput v3, p0, Llyiahf/vczjk/ro4;->OooOOO:I

    iget-object v3, p0, Llyiahf/vczjk/ro4;->OooOoO:Llyiahf/vczjk/xa;

    if-eqz v3, :cond_8

    invoke-virtual {v3}, Llyiahf/vczjk/xa;->getLayoutNodes()Llyiahf/vczjk/or5;

    move-result-object v5

    invoke-virtual {v5, v0}, Llyiahf/vczjk/or5;->OooO0oO(I)Ljava/lang/Object;

    invoke-virtual {v3}, Llyiahf/vczjk/xa;->getLayoutNodes()Llyiahf/vczjk/or5;

    move-result-object v3

    iget v5, p0, Llyiahf/vczjk/ro4;->OooOOO:I

    invoke-virtual {v3, v5, p0}, Llyiahf/vczjk/or5;->OooO0oo(ILjava/lang/Object;)V

    :cond_8
    iget-object v3, v2, Llyiahf/vczjk/jb0;->OooO0o:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/jl5;

    :goto_3
    if-eqz v3, :cond_9

    invoke-virtual {v3}, Llyiahf/vczjk/jl5;->o0OO00O()V

    iget-object v3, v3, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_3

    :cond_9
    invoke-virtual {v2}, Llyiahf/vczjk/jb0;->OooO0o()V

    const/16 v3, 0x8

    invoke-virtual {v2, v3}, Llyiahf/vczjk/jb0;->OooO0o0(I)Z

    move-result v2

    if-eqz v2, :cond_a

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->Oooo000()V

    :cond_a
    invoke-static {p0}, Llyiahf/vczjk/ro4;->OoooOOo(Llyiahf/vczjk/ro4;)V

    iget-object v2, p0, Llyiahf/vczjk/ro4;->OooOoO:Llyiahf/vczjk/xa;

    if-eqz v2, :cond_d

    invoke-static {}, Llyiahf/vczjk/xa;->OooO()Z

    move-result v3

    if-eqz v3, :cond_c

    iget-object v3, v2, Llyiahf/vczjk/xa;->Oooo0oo:Llyiahf/vczjk/q9;

    if-eqz v3, :cond_c

    iget-object v5, v3, Llyiahf/vczjk/q9;->OooO0oo:Llyiahf/vczjk/pr5;

    invoke-virtual {v5, v0}, Llyiahf/vczjk/pr5;->OooO0o0(I)Z

    move-result v6

    iget-object v7, v3, Llyiahf/vczjk/q9;->OooO0OO:Llyiahf/vczjk/xa;

    iget-object v3, v3, Llyiahf/vczjk/q9;->OooO00o:Llyiahf/vczjk/oO0OOo0o;

    if-eqz v6, :cond_b

    invoke-virtual {v3, v7, v0, v1}, Llyiahf/vczjk/oO0OOo0o;->Oooo0(Landroid/view/View;IZ)V

    :cond_b
    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooOo()Llyiahf/vczjk/je8;

    move-result-object v0

    if-eqz v0, :cond_c

    sget-object v1, Llyiahf/vczjk/ve8;->OooOOOo:Llyiahf/vczjk/ze8;

    iget-object v0, v0, Llyiahf/vczjk/je8;->OooOOO0:Llyiahf/vczjk/js5;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/js5;->OooO0O0(Ljava/lang/Object;)Z

    move-result v0

    if-ne v0, v4, :cond_c

    iget v0, p0, Llyiahf/vczjk/ro4;->OooOOO:I

    invoke-virtual {v5, v0}, Llyiahf/vczjk/pr5;->OooO00o(I)Z

    iget v0, p0, Llyiahf/vczjk/ro4;->OooOOO:I

    invoke-virtual {v3, v7, v0, v4}, Llyiahf/vczjk/oO0OOo0o;->Oooo0(Landroid/view/View;IZ)V

    :cond_c
    invoke-virtual {v2}, Llyiahf/vczjk/xa;->getRectManager()Llyiahf/vczjk/zj7;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v1, v1, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    iget-wide v1, v1, Llyiahf/vczjk/kf5;->OooOoO:J

    invoke-virtual {v0, p0, v1, v2, v4}, Llyiahf/vczjk/zj7;->OooO0o(Llyiahf/vczjk/ro4;JZ)V

    :cond_d
    return-void
.end method

.method public final OooO00o()V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OooOoOO:Llyiahf/vczjk/nga;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/nh;->OooO00o()V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO:Llyiahf/vczjk/fp4;

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/fp4;->OooO00o()V

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v1, v0, Llyiahf/vczjk/jb0;->OooO0Oo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/v16;

    iget-object v0, v0, Llyiahf/vczjk/jb0;->OooO0OO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/b04;

    iget-object v0, v0, Llyiahf/vczjk/v16;->OooOoO:Llyiahf/vczjk/v16;

    :goto_0
    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_4

    if-eqz v1, :cond_4

    const/4 v2, 0x1

    iput-boolean v2, v1, Llyiahf/vczjk/v16;->OooOoo0:Z

    iget-object v2, v1, Llyiahf/vczjk/v16;->OoooO00:Llyiahf/vczjk/r16;

    invoke-virtual {v2}, Llyiahf/vczjk/r16;->OooO00o()Ljava/lang/Object;

    iget-object v2, v1, Llyiahf/vczjk/v16;->OoooO0O:Llyiahf/vczjk/sg6;

    if-eqz v2, :cond_3

    iget-object v2, v1, Llyiahf/vczjk/v16;->OoooO:Llyiahf/vczjk/kj3;

    const/4 v3, 0x0

    if-eqz v2, :cond_2

    iput-object v3, v1, Llyiahf/vczjk/v16;->OoooO:Llyiahf/vczjk/kj3;

    :cond_2
    const/4 v2, 0x0

    invoke-virtual {v1, v3, v2}, Llyiahf/vczjk/v16;->o000Ooo(Llyiahf/vczjk/oe3;Z)V

    iget-object v3, v1, Llyiahf/vczjk/v16;->OooOoO0:Llyiahf/vczjk/ro4;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/ro4;->o000oOoO(Z)V

    :cond_3
    iget-object v1, v1, Llyiahf/vczjk/v16;->OooOoO:Llyiahf/vczjk/v16;

    goto :goto_0

    :cond_4
    return-void
.end method

.method public final OooO0O0()V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OooOoOO:Llyiahf/vczjk/nga;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/nh;->OooO0O0()V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO:Llyiahf/vczjk/fp4;

    const/4 v1, 0x1

    if-eqz v0, :cond_1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/fp4;->OooO0o0(Z)V

    :cond_1
    iput-boolean v1, p0, Llyiahf/vczjk/ro4;->Ooooo00:Z

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v1, v0, Llyiahf/vczjk/jb0;->OooO0o0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/cf9;

    :goto_0
    if-eqz v1, :cond_3

    iget-boolean v2, v1, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v2, :cond_2

    invoke-virtual {v1}, Llyiahf/vczjk/jl5;->o000000O()V

    :cond_2
    iget-object v1, v1, Llyiahf/vczjk/jl5;->OooOOo0:Llyiahf/vczjk/jl5;

    goto :goto_0

    :cond_3
    invoke-virtual {v0}, Llyiahf/vczjk/jb0;->OooO0oO()V

    iget-object v0, v0, Llyiahf/vczjk/jb0;->OooO0o0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cf9;

    :goto_1
    if-eqz v0, :cond_5

    iget-boolean v1, v0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v1, :cond_4

    invoke-virtual {v0}, Llyiahf/vczjk/jl5;->oo0o0Oo()V

    :cond_4
    iget-object v0, v0, Llyiahf/vczjk/jl5;->OooOOo0:Llyiahf/vczjk/jl5;

    goto :goto_1

    :cond_5
    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->Oooo00o()Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_6

    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/ro4;->OooOooo:Llyiahf/vczjk/je8;

    iput-boolean v1, p0, Llyiahf/vczjk/ro4;->OooOooO:Z

    :cond_6
    iget-object v0, p0, Llyiahf/vczjk/ro4;->OooOoO:Llyiahf/vczjk/xa;

    if-eqz v0, :cond_7

    invoke-virtual {v0}, Llyiahf/vczjk/xa;->getRectManager()Llyiahf/vczjk/zj7;

    move-result-object v2

    invoke-virtual {v2, p0}, Llyiahf/vczjk/zj7;->OooO0oo(Llyiahf/vczjk/ro4;)V

    invoke-static {}, Llyiahf/vczjk/xa;->OooO()Z

    move-result v2

    if-eqz v2, :cond_7

    iget-object v0, v0, Llyiahf/vczjk/xa;->Oooo0oo:Llyiahf/vczjk/q9;

    if-eqz v0, :cond_7

    iget v2, p0, Llyiahf/vczjk/ro4;->OooOOO:I

    iget-object v3, v0, Llyiahf/vczjk/q9;->OooO0oo:Llyiahf/vczjk/pr5;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/pr5;->OooO0o0(I)Z

    move-result v2

    if-eqz v2, :cond_7

    iget v2, p0, Llyiahf/vczjk/ro4;->OooOOO:I

    iget-object v3, v0, Llyiahf/vczjk/q9;->OooO00o:Llyiahf/vczjk/oO0OOo0o;

    iget-object v0, v0, Llyiahf/vczjk/q9;->OooO0OO:Llyiahf/vczjk/xa;

    invoke-virtual {v3, v0, v2, v1}, Llyiahf/vczjk/oO0OOo0o;->Oooo0(Landroid/view/View;IZ)V

    :cond_7
    return-void
.end method

.method public final OooO0OO(Llyiahf/vczjk/kl5;)V
    .locals 17

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    iput-object v1, v0, Llyiahf/vczjk/ro4;->OoooOOO:Llyiahf/vczjk/kl5;

    iget-object v2, v0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v3, v2, Llyiahf/vczjk/jb0;->OooO0o:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/jl5;

    sget-object v5, Llyiahf/vczjk/n16;->OooO00o:Llyiahf/vczjk/l16;

    if-eq v3, v5, :cond_0

    goto :goto_0

    :cond_0
    const-string v3, "padChain called on already padded chain"

    invoke-static {v3}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :goto_0
    iget-object v3, v2, Llyiahf/vczjk/jb0;->OooO0o:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/jl5;

    iput-object v5, v3, Llyiahf/vczjk/jl5;->OooOOo0:Llyiahf/vczjk/jl5;

    iput-object v3, v5, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    iget-object v3, v2, Llyiahf/vczjk/jb0;->OooO0oO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/ws5;

    if-eqz v3, :cond_1

    iget v6, v3, Llyiahf/vczjk/ws5;->OooOOOO:I

    goto :goto_1

    :cond_1
    const/4 v6, 0x0

    :goto_1
    iget-object v7, v2, Llyiahf/vczjk/jb0;->OooO0oo:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/ws5;

    const/16 v8, 0x10

    if-nez v7, :cond_2

    new-instance v7, Llyiahf/vczjk/ws5;

    new-array v9, v8, [Llyiahf/vczjk/il5;

    invoke-direct {v7, v9}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    :cond_2
    iget v9, v7, Llyiahf/vczjk/ws5;->OooOOOO:I

    if-ge v9, v8, :cond_3

    move v9, v8

    :cond_3
    new-instance v10, Llyiahf/vczjk/ws5;

    new-array v9, v9, [Llyiahf/vczjk/kl5;

    invoke-direct {v10, v9}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    invoke-virtual {v10, v1}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    const/4 v9, 0x0

    move-object v1, v9

    :goto_2
    iget v11, v10, Llyiahf/vczjk/ws5;->OooOOOO:I

    if-eqz v11, :cond_7

    add-int/lit8 v11, v11, -0x1

    invoke-virtual {v10, v11}, Llyiahf/vczjk/ws5;->OooOO0O(I)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Llyiahf/vczjk/kl5;

    instance-of v12, v11, Llyiahf/vczjk/l41;

    if-eqz v12, :cond_4

    check-cast v11, Llyiahf/vczjk/l41;

    iget-object v12, v11, Llyiahf/vczjk/l41;->OooOOO:Llyiahf/vczjk/kl5;

    invoke-virtual {v10, v12}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    iget-object v11, v11, Llyiahf/vczjk/l41;->OooOOO0:Llyiahf/vczjk/kl5;

    invoke-virtual {v10, v11}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_4
    instance-of v12, v11, Llyiahf/vczjk/il5;

    if-eqz v12, :cond_5

    invoke-virtual {v7, v11}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_5
    if-nez v1, :cond_6

    new-instance v1, Llyiahf/vczjk/m16;

    invoke-direct {v1, v7}, Llyiahf/vczjk/m16;-><init>(Llyiahf/vczjk/ws5;)V

    :cond_6
    move-object v12, v1

    invoke-interface {v11, v1}, Llyiahf/vczjk/kl5;->OooO0Oo(Llyiahf/vczjk/oe3;)Z

    move-object v1, v12

    goto :goto_2

    :cond_7
    iget v1, v7, Llyiahf/vczjk/ws5;->OooOOOO:I

    const/4 v10, 0x1

    iget-object v11, v2, Llyiahf/vczjk/jb0;->OooO0o0:Ljava/lang/Object;

    check-cast v11, Llyiahf/vczjk/cf9;

    const-string v12, "expected prior modifier list to be non-empty"

    iget-object v13, v2, Llyiahf/vczjk/jb0;->OooO0O0:Ljava/lang/Object;

    check-cast v13, Llyiahf/vczjk/ro4;

    if-ne v1, v6, :cond_12

    iget-object v1, v5, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    move-object v5, v2

    const/4 v2, 0x0

    :goto_3
    if-eqz v1, :cond_d

    if-ge v2, v6, :cond_d

    if-eqz v3, :cond_c

    iget-object v8, v3, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    aget-object v8, v8, v2

    check-cast v8, Llyiahf/vczjk/il5;

    iget-object v14, v7, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    aget-object v14, v14, v2

    check-cast v14, Llyiahf/vczjk/il5;

    invoke-static {v8, v14}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v15

    if-eqz v15, :cond_8

    const/4 v15, 0x2

    goto :goto_4

    :cond_8
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v15

    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v4

    if-ne v15, v4, :cond_9

    move v15, v10

    goto :goto_4

    :cond_9
    const/4 v15, 0x0

    :goto_4
    if-eqz v15, :cond_b

    if-eq v15, v10, :cond_a

    goto :goto_5

    :cond_a
    invoke-static {v8, v14, v1}, Llyiahf/vczjk/jb0;->OooOO0(Llyiahf/vczjk/il5;Llyiahf/vczjk/il5;Llyiahf/vczjk/jl5;)V

    :goto_5
    iget-object v1, v1, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    add-int/lit8 v2, v2, 0x1

    goto :goto_3

    :cond_b
    iget-object v1, v1, Llyiahf/vczjk/jl5;->OooOOo0:Llyiahf/vczjk/jl5;

    goto :goto_6

    :cond_c
    invoke-static {v12}, Llyiahf/vczjk/ix8;->OooOOOo(Ljava/lang/String;)Llyiahf/vczjk/k61;

    move-result-object v1

    throw v1

    :cond_d
    :goto_6
    if-ge v2, v6, :cond_11

    if-eqz v3, :cond_10

    if-eqz v1, :cond_f

    iget-object v4, v13, Llyiahf/vczjk/ro4;->OoooOOo:Llyiahf/vczjk/kl5;

    if-eqz v4, :cond_e

    move v4, v10

    goto :goto_7

    :cond_e
    const/4 v4, 0x0

    :goto_7
    xor-int/lit8 v6, v4, 0x1

    move-object v4, v5

    move-object v5, v1

    move-object v1, v4

    move-object v4, v7

    invoke-virtual/range {v1 .. v6}, Llyiahf/vczjk/jb0;->OooO0oo(ILlyiahf/vczjk/ws5;Llyiahf/vczjk/ws5;Llyiahf/vczjk/jl5;Z)V

    goto/16 :goto_e

    :cond_f
    const-string v1, "structuralUpdate requires a non-null tail"

    invoke-static {v1}, Llyiahf/vczjk/ix8;->OooOOOo(Ljava/lang/String;)Llyiahf/vczjk/k61;

    move-result-object v1

    throw v1

    :cond_10
    invoke-static {v12}, Llyiahf/vczjk/ix8;->OooOOOo(Ljava/lang/String;)Llyiahf/vczjk/k61;

    move-result-object v1

    throw v1

    :cond_11
    move-object v2, v5

    move-object v4, v7

    goto :goto_c

    :cond_12
    move-object v4, v7

    iget-object v7, v13, Llyiahf/vczjk/ro4;->OoooOOo:Llyiahf/vczjk/kl5;

    if-eqz v7, :cond_15

    if-nez v6, :cond_15

    const/4 v1, 0x0

    :goto_8
    iget v6, v4, Llyiahf/vczjk/ws5;->OooOOOO:I

    if-ge v1, v6, :cond_13

    iget-object v6, v4, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    aget-object v6, v6, v1

    check-cast v6, Llyiahf/vczjk/il5;

    invoke-static {v6, v5}, Llyiahf/vczjk/jb0;->OooO0OO(Llyiahf/vczjk/il5;Llyiahf/vczjk/jl5;)Llyiahf/vczjk/jl5;

    move-result-object v5

    add-int/lit8 v1, v1, 0x1

    goto :goto_8

    :cond_13
    iget-object v1, v11, Llyiahf/vczjk/jl5;->OooOOo0:Llyiahf/vczjk/jl5;

    const/16 v16, 0x0

    :goto_9
    if-eqz v1, :cond_14

    sget-object v5, Llyiahf/vczjk/n16;->OooO00o:Llyiahf/vczjk/l16;

    if-eq v1, v5, :cond_14

    iget v5, v1, Llyiahf/vczjk/jl5;->OooOOOO:I

    or-int v5, v16, v5

    iput v5, v1, Llyiahf/vczjk/jl5;->OooOOOo:I

    iget-object v1, v1, Llyiahf/vczjk/jl5;->OooOOo0:Llyiahf/vczjk/jl5;

    move/from16 v16, v5

    goto :goto_9

    :cond_14
    move-object v1, v2

    goto :goto_e

    :cond_15
    if-nez v1, :cond_19

    if-eqz v3, :cond_18

    iget-object v1, v5, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    const/4 v5, 0x0

    :goto_a
    if-eqz v1, :cond_16

    iget v6, v3, Llyiahf/vczjk/ws5;->OooOOOO:I

    if-ge v5, v6, :cond_16

    invoke-static {v1}, Llyiahf/vczjk/jb0;->OooO0Oo(Llyiahf/vczjk/jl5;)Llyiahf/vczjk/jl5;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    add-int/lit8 v5, v5, 0x1

    goto :goto_a

    :cond_16
    invoke-virtual {v13}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v1

    if-eqz v1, :cond_17

    iget-object v1, v1, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v1, v1, Llyiahf/vczjk/jb0;->OooO0OO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/b04;

    goto :goto_b

    :cond_17
    move-object v1, v9

    :goto_b
    iget-object v5, v2, Llyiahf/vczjk/jb0;->OooO0OO:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/b04;

    iput-object v1, v5, Llyiahf/vczjk/v16;->OooOoOO:Llyiahf/vczjk/v16;

    iput-object v5, v2, Llyiahf/vczjk/jb0;->OooO0Oo:Ljava/lang/Object;

    :goto_c
    move-object v1, v2

    const/4 v10, 0x0

    goto :goto_e

    :cond_18
    invoke-static {v12}, Llyiahf/vczjk/ix8;->OooOOOo(Ljava/lang/String;)Llyiahf/vczjk/k61;

    move-result-object v1

    throw v1

    :cond_19
    if-nez v3, :cond_1a

    new-instance v3, Llyiahf/vczjk/ws5;

    new-array v1, v8, [Llyiahf/vczjk/il5;

    invoke-direct {v3, v1}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    :cond_1a
    if-eqz v7, :cond_1b

    move/from16 v16, v10

    goto :goto_d

    :cond_1b
    const/16 v16, 0x0

    :goto_d
    xor-int/lit8 v6, v16, 0x1

    move-object v1, v2

    const/4 v2, 0x0

    invoke-virtual/range {v1 .. v6}, Llyiahf/vczjk/jb0;->OooO0oo(ILlyiahf/vczjk/ws5;Llyiahf/vczjk/ws5;Llyiahf/vczjk/jl5;Z)V

    :goto_e
    iput-object v4, v1, Llyiahf/vczjk/jb0;->OooO0oO:Ljava/lang/Object;

    if-eqz v3, :cond_1c

    invoke-virtual {v3}, Llyiahf/vczjk/ws5;->OooO0oO()V

    goto :goto_f

    :cond_1c
    move-object v3, v9

    :goto_f
    iput-object v3, v1, Llyiahf/vczjk/jb0;->OooO0oo:Ljava/lang/Object;

    sget-object v2, Llyiahf/vczjk/n16;->OooO00o:Llyiahf/vczjk/l16;

    iget-object v3, v2, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    if-nez v3, :cond_1d

    goto :goto_10

    :cond_1d
    move-object v11, v3

    :goto_10
    iput-object v9, v11, Llyiahf/vczjk/jl5;->OooOOo0:Llyiahf/vczjk/jl5;

    iput-object v9, v2, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    const/4 v3, -0x1

    iput v3, v2, Llyiahf/vczjk/jl5;->OooOOOo:I

    iput-object v9, v2, Llyiahf/vczjk/jl5;->OooOo00:Llyiahf/vczjk/v16;

    if-eq v11, v2, :cond_1e

    goto :goto_11

    :cond_1e
    const-string v2, "trimChain did not update the head"

    invoke-static {v2}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :goto_11
    iput-object v11, v1, Llyiahf/vczjk/jb0;->OooO0o:Ljava/lang/Object;

    if-eqz v10, :cond_1f

    invoke-virtual {v1}, Llyiahf/vczjk/jb0;->OooO()V

    :cond_1f
    iget-object v2, v0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    invoke-virtual {v2}, Llyiahf/vczjk/vo4;->OooO()V

    iget-object v2, v0, Llyiahf/vczjk/ro4;->OooOo00:Llyiahf/vczjk/ro4;

    if-nez v2, :cond_20

    const/16 v2, 0x200

    invoke-virtual {v1, v2}, Llyiahf/vczjk/jb0;->OooO0o0(I)Z

    move-result v1

    if-eqz v1, :cond_20

    invoke-virtual {v0, v0}, Llyiahf/vczjk/ro4;->OoooOoo(Llyiahf/vczjk/ro4;)V

    :cond_20
    return-void
.end method

.method public final OooO0Oo(Llyiahf/vczjk/xa;)V
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OooOoO:Llyiahf/vczjk/xa;

    const/4 v1, 0x0

    const/4 v2, 0x1

    if-nez v0, :cond_0

    move v0, v2

    goto :goto_0

    :cond_0
    move v0, v1

    :goto_0
    if-nez v0, :cond_1

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v3, "Cannot attach "

    invoke-direct {v0, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v3, " as it already is attached.  Tree: "

    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p0, v1}, Llyiahf/vczjk/ro4;->OooO0oO(I)Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/ro4;->OooOoO0:Llyiahf/vczjk/ro4;

    const/4 v3, 0x0

    if-eqz v0, :cond_5

    iget-object v0, v0, Llyiahf/vczjk/ro4;->OooOoO:Llyiahf/vczjk/xa;

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_2

    goto :goto_3

    :cond_2
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v4, "Attaching to a different owner("

    invoke-direct {v0, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v4, ") than the parent\'s owner("

    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v4

    if-eqz v4, :cond_3

    iget-object v4, v4, Llyiahf/vczjk/ro4;->OooOoO:Llyiahf/vczjk/xa;

    goto :goto_1

    :cond_3
    move-object v4, v3

    :goto_1
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v4, "). This tree: "

    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p0, v1}, Llyiahf/vczjk/ro4;->OooO0oO(I)Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v4, " Parent tree: "

    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v4, p0, Llyiahf/vczjk/ro4;->OooOoO0:Llyiahf/vczjk/ro4;

    if-eqz v4, :cond_4

    invoke-virtual {v4, v1}, Llyiahf/vczjk/ro4;->OooO0oO(I)Ljava/lang/String;

    move-result-object v4

    goto :goto_2

    :cond_4
    move-object v4, v3

    :goto_2
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_5
    :goto_3
    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v0

    iget-object v4, p0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    if-nez v0, :cond_6

    iget-object v5, v4, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    iput-boolean v2, v5, Llyiahf/vczjk/kf5;->Oooo000:Z

    iget-object v5, v4, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    if-eqz v5, :cond_6

    sget-object v6, Llyiahf/vczjk/s65;->OooOOO0:Llyiahf/vczjk/s65;

    iput-object v6, v5, Llyiahf/vczjk/w65;->OooOooO:Llyiahf/vczjk/s65;

    :cond_6
    iget-object v5, p0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v6, v5, Llyiahf/vczjk/jb0;->OooO0Oo:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/v16;

    if-eqz v0, :cond_7

    iget-object v7, v0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v7, v7, Llyiahf/vczjk/jb0;->OooO0OO:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/b04;

    goto :goto_4

    :cond_7
    move-object v7, v3

    :goto_4
    iput-object v7, v6, Llyiahf/vczjk/v16;->OooOoOO:Llyiahf/vczjk/v16;

    iput-object p1, p0, Llyiahf/vczjk/ro4;->OooOoO:Llyiahf/vczjk/xa;

    if-eqz v0, :cond_8

    iget v6, v0, Llyiahf/vczjk/ro4;->OooOoo0:I

    goto :goto_5

    :cond_8
    const/4 v6, -0x1

    :goto_5
    add-int/2addr v6, v2

    iput v6, p0, Llyiahf/vczjk/ro4;->OooOoo0:I

    iget-object v6, p0, Llyiahf/vczjk/ro4;->OoooOOo:Llyiahf/vczjk/kl5;

    if-eqz v6, :cond_9

    invoke-virtual {p0, v6}, Llyiahf/vczjk/ro4;->OooO0OO(Llyiahf/vczjk/kl5;)V

    :cond_9
    iput-object v3, p0, Llyiahf/vczjk/ro4;->OoooOOo:Llyiahf/vczjk/kl5;

    invoke-virtual {p1}, Llyiahf/vczjk/xa;->getLayoutNodes()Llyiahf/vczjk/or5;

    move-result-object v3

    iget v6, p0, Llyiahf/vczjk/ro4;->OooOOO:I

    invoke-virtual {v3, v6, p0}, Llyiahf/vczjk/or5;->OooO0oo(ILjava/lang/Object;)V

    iget-object v3, p0, Llyiahf/vczjk/ro4;->OooOoO0:Llyiahf/vczjk/ro4;

    if-eqz v3, :cond_a

    iget-object v3, v3, Llyiahf/vczjk/ro4;->OooOo00:Llyiahf/vczjk/ro4;

    if-nez v3, :cond_b

    :cond_a
    iget-object v3, p0, Llyiahf/vczjk/ro4;->OooOo00:Llyiahf/vczjk/ro4;

    :cond_b
    invoke-virtual {p0, v3}, Llyiahf/vczjk/ro4;->OoooOoo(Llyiahf/vczjk/ro4;)V

    iget-object v3, p0, Llyiahf/vczjk/ro4;->OooOo00:Llyiahf/vczjk/ro4;

    if-nez v3, :cond_c

    const/16 v3, 0x200

    invoke-virtual {v5, v3}, Llyiahf/vczjk/jb0;->OooO0o0(I)Z

    move-result v3

    if-eqz v3, :cond_c

    invoke-virtual {p0, p0}, Llyiahf/vczjk/ro4;->OoooOoo(Llyiahf/vczjk/ro4;)V

    :cond_c
    iget-boolean v3, p0, Llyiahf/vczjk/ro4;->Ooooo00:Z

    if-nez v3, :cond_d

    iget-object v3, v5, Llyiahf/vczjk/jb0;->OooO0o:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/jl5;

    :goto_6
    if-eqz v3, :cond_d

    invoke-virtual {v3}, Llyiahf/vczjk/jl5;->o0OO00O()V

    iget-object v3, v3, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_6

    :cond_d
    iget-object v3, p0, Llyiahf/vczjk/ro4;->OooOo0O:Llyiahf/vczjk/era;

    iget-object v3, v3, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/ws5;

    iget-object v6, v3, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v3, v3, Llyiahf/vczjk/ws5;->OooOOOO:I

    :goto_7
    if-ge v1, v3, :cond_e

    aget-object v7, v6, v1

    check-cast v7, Llyiahf/vczjk/ro4;

    invoke-virtual {v7, p1}, Llyiahf/vczjk/ro4;->OooO0Oo(Llyiahf/vczjk/xa;)V

    add-int/lit8 v1, v1, 0x1

    goto :goto_7

    :cond_e
    iget-boolean v1, p0, Llyiahf/vczjk/ro4;->Ooooo00:Z

    if-nez v1, :cond_f

    invoke-virtual {v5}, Llyiahf/vczjk/jb0;->OooO0o()V

    :cond_f
    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooOooo()V

    if-eqz v0, :cond_10

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOooo()V

    :cond_10
    iget-object v0, v5, Llyiahf/vczjk/jb0;->OooO0Oo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/v16;

    iget-object v1, v5, Llyiahf/vczjk/jb0;->OooO0OO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/b04;

    iget-object v1, v1, Llyiahf/vczjk/v16;->OooOoO:Llyiahf/vczjk/v16;

    :goto_8
    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_12

    if-eqz v0, :cond_12

    iget-object v3, v0, Llyiahf/vczjk/v16;->OooOooO:Llyiahf/vczjk/oe3;

    invoke-virtual {v0, v3, v2}, Llyiahf/vczjk/v16;->o000Ooo(Llyiahf/vczjk/oe3;Z)V

    iget-object v3, v0, Llyiahf/vczjk/v16;->OoooO0O:Llyiahf/vczjk/sg6;

    if-eqz v3, :cond_11

    invoke-interface {v3}, Llyiahf/vczjk/sg6;->invalidate()V

    :cond_11
    iget-object v0, v0, Llyiahf/vczjk/v16;->OooOoO:Llyiahf/vczjk/v16;

    goto :goto_8

    :cond_12
    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooOo0:Llyiahf/vczjk/dh;

    if-eqz v0, :cond_13

    invoke-virtual {v0, p1}, Llyiahf/vczjk/dh;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_13
    invoke-virtual {v4}, Llyiahf/vczjk/vo4;->OooO()V

    iget-boolean v0, p0, Llyiahf/vczjk/ro4;->Ooooo00:Z

    if-nez v0, :cond_14

    const/16 v0, 0x8

    invoke-virtual {v5, v0}, Llyiahf/vczjk/jb0;->OooO0o0(I)Z

    move-result v0

    if-eqz v0, :cond_14

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->Oooo000()V

    :cond_14
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {}, Llyiahf/vczjk/xa;->OooO()Z

    move-result v0

    if-eqz v0, :cond_15

    iget-object p1, p1, Llyiahf/vczjk/xa;->Oooo0oo:Llyiahf/vczjk/q9;

    if-eqz p1, :cond_15

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooOo()Llyiahf/vczjk/je8;

    move-result-object v0

    if-eqz v0, :cond_15

    sget-object v1, Llyiahf/vczjk/ve8;->OooOOOo:Llyiahf/vczjk/ze8;

    iget-object v0, v0, Llyiahf/vczjk/je8;->OooOOO0:Llyiahf/vczjk/js5;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/js5;->OooO0O0(Ljava/lang/Object;)Z

    move-result v0

    if-ne v0, v2, :cond_15

    iget v0, p0, Llyiahf/vczjk/ro4;->OooOOO:I

    iget-object v1, p1, Llyiahf/vczjk/q9;->OooO0oo:Llyiahf/vczjk/pr5;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/pr5;->OooO00o(I)Z

    iget v0, p0, Llyiahf/vczjk/ro4;->OooOOO:I

    iget-object v1, p1, Llyiahf/vczjk/q9;->OooO00o:Llyiahf/vczjk/oO0OOo0o;

    iget-object p1, p1, Llyiahf/vczjk/q9;->OooO0OO:Llyiahf/vczjk/xa;

    invoke-virtual {v1, p1, v0, v2}, Llyiahf/vczjk/oO0OOo0o;->Oooo0(Landroid/view/View;IZ)V

    :cond_15
    return-void
.end method

.method public final OooO0o()V
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/ro4;->Oooo0oo:Llyiahf/vczjk/no4;

    iput-object v0, p0, Llyiahf/vczjk/ro4;->Oooo:Llyiahf/vczjk/no4;

    sget-object v0, Llyiahf/vczjk/no4;->OooOOOO:Llyiahf/vczjk/no4;

    iput-object v0, p0, Llyiahf/vczjk/ro4;->Oooo0oo:Llyiahf/vczjk/no4;

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooOoO()Llyiahf/vczjk/ws5;

    move-result-object v0

    iget-object v1, v0, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v0, v0, Llyiahf/vczjk/ws5;->OooOOOO:I

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v0, :cond_1

    aget-object v3, v1, v2

    check-cast v3, Llyiahf/vczjk/ro4;

    iget-object v4, v3, Llyiahf/vczjk/ro4;->Oooo0oo:Llyiahf/vczjk/no4;

    sget-object v5, Llyiahf/vczjk/no4;->OooOOO:Llyiahf/vczjk/no4;

    if-ne v4, v5, :cond_0

    invoke-virtual {v3}, Llyiahf/vczjk/ro4;->OooO0o()V

    :cond_0
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_1
    return-void
.end method

.method public final OooO0o0()V
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/ro4;->Oooo0oo:Llyiahf/vczjk/no4;

    iput-object v0, p0, Llyiahf/vczjk/ro4;->Oooo:Llyiahf/vczjk/no4;

    sget-object v0, Llyiahf/vczjk/no4;->OooOOOO:Llyiahf/vczjk/no4;

    iput-object v0, p0, Llyiahf/vczjk/ro4;->Oooo0oo:Llyiahf/vczjk/no4;

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooOoO()Llyiahf/vczjk/ws5;

    move-result-object v0

    iget-object v1, v0, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v0, v0, Llyiahf/vczjk/ws5;->OooOOOO:I

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v0, :cond_1

    aget-object v3, v1, v2

    check-cast v3, Llyiahf/vczjk/ro4;

    iget-object v4, v3, Llyiahf/vczjk/ro4;->Oooo0oo:Llyiahf/vczjk/no4;

    sget-object v5, Llyiahf/vczjk/no4;->OooOOOO:Llyiahf/vczjk/no4;

    if-eq v4, v5, :cond_0

    invoke-virtual {v3}, Llyiahf/vczjk/ro4;->OooO0o0()V

    :cond_0
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_1
    return-void
.end method

.method public final OooO0oO(I)Ljava/lang/String;
    .locals 7

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const/4 v1, 0x0

    move v2, v1

    :goto_0
    if-ge v2, p1, :cond_0

    const-string v3, "  "

    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_0
    const-string v2, "|-"

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v2, 0xa

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooOoO()Llyiahf/vczjk/ws5;

    move-result-object v2

    iget-object v3, v2, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v2, v2, Llyiahf/vczjk/ws5;->OooOOOO:I

    move v4, v1

    :goto_1
    if-ge v4, v2, :cond_1

    aget-object v5, v3, v4

    check-cast v5, Llyiahf/vczjk/ro4;

    add-int/lit8 v6, p1, 0x1

    invoke-virtual {v5, v6}, Llyiahf/vczjk/ro4;->OooO0oO(I)Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    add-int/lit8 v4, v4, 0x1

    goto :goto_1

    :cond_1
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    if-nez p1, :cond_2

    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result p1

    add-int/lit8 p1, p1, -0x1

    invoke-virtual {v0, v1, p1}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object p1

    const-string v0, "substring(...)"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1

    :cond_2
    return-object v0
.end method

.method public final OooO0oo()V
    .locals 10

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OooOoO:Llyiahf/vczjk/xa;

    const/4 v1, 0x0

    const/4 v2, 0x0

    if-nez v0, :cond_1

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v3, "Cannot detach node that is already detached!  Tree: "

    invoke-direct {v0, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v3

    if-eqz v3, :cond_0

    invoke-virtual {v3, v2}, Llyiahf/vczjk/ro4;->OooO0oO(I)Ljava/lang/String;

    move-result-object v1

    :cond_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0OO(Ljava/lang/String;)Ljava/lang/Void;

    new-instance v0, Llyiahf/vczjk/k61;

    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    throw v0

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v3

    iget-object v4, p0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    if-eqz v3, :cond_2

    invoke-virtual {v3}, Llyiahf/vczjk/ro4;->OooOoo()V

    invoke-virtual {v3}, Llyiahf/vczjk/ro4;->OooOooo()V

    iget-object v3, v4, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    sget-object v5, Llyiahf/vczjk/no4;->OooOOOO:Llyiahf/vczjk/no4;

    iput-object v5, v3, Llyiahf/vczjk/kf5;->OooOo:Llyiahf/vczjk/no4;

    iget-object v3, v4, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    if-eqz v3, :cond_2

    iput-object v5, v3, Llyiahf/vczjk/w65;->OooOo0O:Llyiahf/vczjk/no4;

    :cond_2
    iget-object v3, v4, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    iget-object v3, v3, Llyiahf/vczjk/kf5;->Oooo0OO:Llyiahf/vczjk/so4;

    const/4 v5, 0x1

    iput-boolean v5, v3, Llyiahf/vczjk/v4;->OooO0O0:Z

    iput-boolean v2, v3, Llyiahf/vczjk/v4;->OooO0OO:Z

    iput-boolean v2, v3, Llyiahf/vczjk/v4;->OooO0o0:Z

    iput-boolean v2, v3, Llyiahf/vczjk/v4;->OooO0Oo:Z

    iput-boolean v2, v3, Llyiahf/vczjk/v4;->OooO0o:Z

    iput-boolean v2, v3, Llyiahf/vczjk/v4;->OooO0oO:Z

    iput-object v1, v3, Llyiahf/vczjk/v4;->OooO0oo:Llyiahf/vczjk/w4;

    iget-object v3, v4, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    if-eqz v3, :cond_3

    iget-object v3, v3, Llyiahf/vczjk/w65;->OooOooo:Llyiahf/vczjk/so4;

    if-eqz v3, :cond_3

    iput-boolean v5, v3, Llyiahf/vczjk/v4;->OooO0O0:Z

    iput-boolean v2, v3, Llyiahf/vczjk/v4;->OooO0OO:Z

    iput-boolean v2, v3, Llyiahf/vczjk/v4;->OooO0o0:Z

    iput-boolean v2, v3, Llyiahf/vczjk/v4;->OooO0Oo:Z

    iput-boolean v2, v3, Llyiahf/vczjk/v4;->OooO0o:Z

    iput-boolean v2, v3, Llyiahf/vczjk/v4;->OooO0oO:Z

    iput-object v1, v3, Llyiahf/vczjk/v4;->OooO0oo:Llyiahf/vczjk/w4;

    :cond_3
    iget-object v3, p0, Llyiahf/vczjk/ro4;->OoooOoO:Llyiahf/vczjk/eh;

    if-eqz v3, :cond_4

    invoke-virtual {v3, v0}, Llyiahf/vczjk/eh;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_4
    iget-object v3, p0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    invoke-virtual {v3}, Llyiahf/vczjk/jb0;->OooO0oO()V

    iput-boolean v5, p0, Llyiahf/vczjk/ro4;->OooOoo:Z

    iget-object v6, p0, Llyiahf/vczjk/ro4;->OooOo0O:Llyiahf/vczjk/era;

    iget-object v6, v6, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/ws5;

    iget-object v7, v6, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v6, v6, Llyiahf/vczjk/ws5;->OooOOOO:I

    move v8, v2

    :goto_0
    if-ge v8, v6, :cond_5

    aget-object v9, v7, v8

    check-cast v9, Llyiahf/vczjk/ro4;

    invoke-virtual {v9}, Llyiahf/vczjk/ro4;->OooO0oo()V

    add-int/lit8 v8, v8, 0x1

    goto :goto_0

    :cond_5
    iput-boolean v2, p0, Llyiahf/vczjk/ro4;->OooOoo:Z

    iget-object v6, v3, Llyiahf/vczjk/jb0;->OooO0o0:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/cf9;

    :goto_1
    if-eqz v6, :cond_7

    iget-boolean v7, v6, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v7, :cond_6

    invoke-virtual {v6}, Llyiahf/vczjk/jl5;->oo0o0Oo()V

    :cond_6
    iget-object v6, v6, Llyiahf/vczjk/jl5;->OooOOo0:Llyiahf/vczjk/jl5;

    goto :goto_1

    :cond_7
    invoke-virtual {v0}, Llyiahf/vczjk/xa;->getLayoutNodes()Llyiahf/vczjk/or5;

    move-result-object v6

    iget v7, p0, Llyiahf/vczjk/ro4;->OooOOO:I

    invoke-virtual {v6, v7}, Llyiahf/vczjk/or5;->OooO0oO(I)Ljava/lang/Object;

    iget-object v6, v0, Llyiahf/vczjk/xa;->OoooOo0:Llyiahf/vczjk/gf5;

    iget-object v7, v6, Llyiahf/vczjk/gf5;->OooO0O0:Llyiahf/vczjk/era;

    iget-object v8, v7, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v8, Llyiahf/vczjk/oO0OOo0o;

    invoke-virtual {v8, p0}, Llyiahf/vczjk/oO0OOo0o;->Oooo0OO(Llyiahf/vczjk/ro4;)Z

    iget-object v7, v7, Llyiahf/vczjk/era;->OooOOO:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/oO0OOo0o;

    invoke-virtual {v7, p0}, Llyiahf/vczjk/oO0OOo0o;->Oooo0OO(Llyiahf/vczjk/ro4;)Z

    iget-object v6, v6, Llyiahf/vczjk/gf5;->OooO0o0:Llyiahf/vczjk/a27;

    iget-object v6, v6, Llyiahf/vczjk/a27;->OooOOO:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/ws5;

    invoke-virtual {v6, p0}, Llyiahf/vczjk/ws5;->OooOO0(Ljava/lang/Object;)Z

    iput-boolean v5, v0, Llyiahf/vczjk/xa;->Oooo:Z

    invoke-virtual {v0}, Llyiahf/vczjk/xa;->getRectManager()Llyiahf/vczjk/zj7;

    move-result-object v5

    invoke-virtual {v5, p0}, Llyiahf/vczjk/zj7;->OooO0oo(Llyiahf/vczjk/ro4;)V

    invoke-static {}, Llyiahf/vczjk/xa;->OooO()Z

    move-result v5

    if-eqz v5, :cond_8

    iget-object v5, v0, Llyiahf/vczjk/xa;->Oooo0oo:Llyiahf/vczjk/q9;

    if-eqz v5, :cond_8

    iget v6, p0, Llyiahf/vczjk/ro4;->OooOOO:I

    iget-object v7, v5, Llyiahf/vczjk/q9;->OooO0oo:Llyiahf/vczjk/pr5;

    invoke-virtual {v7, v6}, Llyiahf/vczjk/pr5;->OooO0o0(I)Z

    move-result v6

    if-eqz v6, :cond_8

    iget v6, p0, Llyiahf/vczjk/ro4;->OooOOO:I

    iget-object v7, v5, Llyiahf/vczjk/q9;->OooO00o:Llyiahf/vczjk/oO0OOo0o;

    iget-object v5, v5, Llyiahf/vczjk/q9;->OooO0OO:Llyiahf/vczjk/xa;

    invoke-virtual {v7, v5, v6, v2}, Llyiahf/vczjk/oO0OOo0o;->Oooo0(Landroid/view/View;IZ)V

    :cond_8
    iput-object v1, p0, Llyiahf/vczjk/ro4;->OooOoO:Llyiahf/vczjk/xa;

    invoke-virtual {p0, v1}, Llyiahf/vczjk/ro4;->OoooOoo(Llyiahf/vczjk/ro4;)V

    iput v2, p0, Llyiahf/vczjk/ro4;->OooOoo0:I

    iget-object v5, v4, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    const v6, 0x7fffffff

    iput v6, v5, Llyiahf/vczjk/kf5;->OooOo0:I

    iput v6, v5, Llyiahf/vczjk/kf5;->OooOo00:I

    iput-boolean v2, v5, Llyiahf/vczjk/kf5;->Oooo000:Z

    iget-object v4, v4, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    if-eqz v4, :cond_9

    iput v6, v4, Llyiahf/vczjk/w65;->OooOo0:I

    iput v6, v4, Llyiahf/vczjk/w65;->OooOo00:I

    sget-object v5, Llyiahf/vczjk/s65;->OooOOOO:Llyiahf/vczjk/s65;

    iput-object v5, v4, Llyiahf/vczjk/w65;->OooOooO:Llyiahf/vczjk/s65;

    :cond_9
    const/16 v4, 0x8

    invoke-virtual {v3, v4}, Llyiahf/vczjk/jb0;->OooO0o0(I)Z

    move-result v3

    if-eqz v3, :cond_a

    iget-object v3, p0, Llyiahf/vczjk/ro4;->OooOooo:Llyiahf/vczjk/je8;

    iput-object v1, p0, Llyiahf/vczjk/ro4;->OooOooo:Llyiahf/vczjk/je8;

    iput-boolean v2, p0, Llyiahf/vczjk/ro4;->OooOooO:Z

    invoke-virtual {v0}, Llyiahf/vczjk/xa;->getSemanticsOwner()Llyiahf/vczjk/ue8;

    move-result-object v1

    invoke-virtual {v1, p0, v3}, Llyiahf/vczjk/ue8;->OooO0O0(Llyiahf/vczjk/ro4;Llyiahf/vczjk/je8;)V

    invoke-virtual {v0}, Llyiahf/vczjk/xa;->OooOooO()V

    :cond_a
    return-void
.end method

.method public final OooOO0(Llyiahf/vczjk/eq0;Llyiahf/vczjk/kj3;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v0, v0, Llyiahf/vczjk/jb0;->OooO0Oo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/v16;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/v16;->o00000oO(Llyiahf/vczjk/eq0;Llyiahf/vczjk/kj3;)V

    return-void
.end method

.method public final OooOO0o()V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OooOo00:Llyiahf/vczjk/ro4;

    const/4 v1, 0x0

    const/4 v2, 0x5

    if-eqz v0, :cond_0

    invoke-static {p0, v1, v2}, Llyiahf/vczjk/ro4;->OoooOO0(Llyiahf/vczjk/ro4;ZI)V

    goto :goto_0

    :cond_0
    invoke-static {p0, v1, v2}, Llyiahf/vczjk/ro4;->OoooOOO(Llyiahf/vczjk/ro4;ZI)V

    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    iget-boolean v1, v0, Llyiahf/vczjk/kf5;->OooOo0O:Z

    if-eqz v1, :cond_1

    iget-wide v0, v0, Llyiahf/vczjk/ow6;->OooOOOo:J

    new-instance v2, Llyiahf/vczjk/rk1;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/rk1;-><init>(J)V

    goto :goto_1

    :cond_1
    const/4 v2, 0x0

    :goto_1
    if-eqz v2, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OooOoO:Llyiahf/vczjk/xa;

    if-eqz v0, :cond_3

    iget-wide v1, v2, Llyiahf/vczjk/rk1;->OooO00o:J

    invoke-virtual {v0, p0, v1, v2}, Llyiahf/vczjk/xa;->OooOo0o(Llyiahf/vczjk/ro4;J)V

    return-void

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/ro4;->OooOoO:Llyiahf/vczjk/xa;

    if-eqz v0, :cond_3

    const/4 v1, 0x1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/xa;->OooOo0O(Z)V

    :cond_3
    return-void
.end method

.method public final OooOOO()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    invoke-virtual {v0}, Llyiahf/vczjk/kf5;->o00oO0O()Ljava/util/List;

    move-result-object v0

    return-object v0
.end method

.method public final OooOOO0()Ljava/util/List;
    .locals 10

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object v1, v0, Llyiahf/vczjk/w65;->OooOOo:Llyiahf/vczjk/vo4;

    iget-object v2, v1, Llyiahf/vczjk/vo4;->OooO00o:Llyiahf/vczjk/ro4;

    invoke-virtual {v2}, Llyiahf/vczjk/ro4;->OooOOOO()Ljava/util/List;

    iget-boolean v2, v0, Llyiahf/vczjk/w65;->Oooo00O:Z

    iget-object v3, v0, Llyiahf/vczjk/w65;->Oooo000:Llyiahf/vczjk/ws5;

    if-nez v2, :cond_0

    invoke-virtual {v3}, Llyiahf/vczjk/ws5;->OooO0o()Ljava/util/List;

    move-result-object v0

    return-object v0

    :cond_0
    iget-object v1, v1, Llyiahf/vczjk/vo4;->OooO00o:Llyiahf/vczjk/ro4;

    invoke-virtual {v1}, Llyiahf/vczjk/ro4;->OooOoO()Llyiahf/vczjk/ws5;

    move-result-object v2

    iget-object v4, v2, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v2, v2, Llyiahf/vczjk/ws5;->OooOOOO:I

    const/4 v5, 0x0

    move v6, v5

    :goto_0
    if-ge v6, v2, :cond_2

    aget-object v7, v4, v6

    check-cast v7, Llyiahf/vczjk/ro4;

    iget v8, v3, Llyiahf/vczjk/ws5;->OooOOOO:I

    if-gt v8, v6, :cond_1

    iget-object v7, v7, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v7, v7, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    invoke-static {v7}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v3, v7}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_1
    iget-object v7, v7, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v7, v7, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    invoke-static {v7}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object v8, v3, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    aget-object v9, v8, v6

    aput-object v7, v8, v6

    :goto_1
    add-int/lit8 v6, v6, 0x1

    goto :goto_0

    :cond_2
    invoke-virtual {v1}, Llyiahf/vczjk/ro4;->OooOOOO()Ljava/util/List;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ts5;

    iget-object v1, v1, Llyiahf/vczjk/ts5;->OooOOO0:Llyiahf/vczjk/ws5;

    iget v1, v1, Llyiahf/vczjk/ws5;->OooOOOO:I

    iget v2, v3, Llyiahf/vczjk/ws5;->OooOOOO:I

    invoke-virtual {v3, v1, v2}, Llyiahf/vczjk/ws5;->OooOO0o(II)V

    iput-boolean v5, v0, Llyiahf/vczjk/w65;->Oooo00O:Z

    invoke-virtual {v3}, Llyiahf/vczjk/ws5;->OooO0o()Ljava/util/List;

    move-result-object v0

    return-object v0
.end method

.method public final OooOOOO()Ljava/util/List;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooOoO()Llyiahf/vczjk/ws5;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/ws5;->OooO0o()Ljava/util/List;

    move-result-object v0

    return-object v0
.end method

.method public final OooOOOo()Z
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->Oooo00o()Z

    move-result v0

    return v0
.end method

.method public final OooOOo()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    iget-boolean v0, v0, Llyiahf/vczjk/kf5;->Oooo0:Z

    return v0
.end method

.method public final OooOOo0()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OooOo0O:Llyiahf/vczjk/era;

    iget-object v0, v0, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ws5;

    invoke-virtual {v0}, Llyiahf/vczjk/ws5;->OooO0o()Ljava/util/List;

    move-result-object v0

    return-object v0
.end method

.method public final OooOOoo()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    iget-boolean v0, v0, Llyiahf/vczjk/kf5;->Oooo00o:Z

    return v0
.end method

.method public final OooOo()Llyiahf/vczjk/je8;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->Oooo00o()Z

    move-result v0

    if-eqz v0, :cond_1

    iget-boolean v0, p0, Llyiahf/vczjk/ro4;->Ooooo00:Z

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    const/16 v1, 0x8

    invoke-virtual {v0, v1}, Llyiahf/vczjk/jb0;->OooO0o0(I)Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/ro4;->OooOooo:Llyiahf/vczjk/je8;

    return-object v0

    :cond_1
    :goto_0
    const/4 v0, 0x0

    return-object v0
.end method

.method public final OooOo0()Llyiahf/vczjk/era;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ro4;->Oooo0O0:Llyiahf/vczjk/era;

    if-nez v0, :cond_0

    new-instance v0, Llyiahf/vczjk/era;

    iget-object v1, p0, Llyiahf/vczjk/ro4;->Oooo0:Llyiahf/vczjk/lf5;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object p0, v0, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    invoke-static {v1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v1

    iput-object v1, v0, Llyiahf/vczjk/era;->OooOOO:Ljava/lang/Object;

    iput-object v0, p0, Llyiahf/vczjk/ro4;->Oooo0O0:Llyiahf/vczjk/era;

    :cond_0
    return-object v0
.end method

.method public final OooOo00()Llyiahf/vczjk/no4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    if-eqz v0, :cond_1

    iget-object v0, v0, Llyiahf/vczjk/w65;->OooOo0O:Llyiahf/vczjk/no4;

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    return-object v0

    :cond_1
    :goto_0
    sget-object v0, Llyiahf/vczjk/no4;->OooOOOO:Llyiahf/vczjk/no4;

    return-object v0
.end method

.method public final OooOo0O()Llyiahf/vczjk/ro4;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OooOoO0:Llyiahf/vczjk/ro4;

    :goto_0
    if-eqz v0, :cond_0

    iget-boolean v1, v0, Llyiahf/vczjk/ro4;->OooOOO0:Z

    const/4 v2, 0x1

    if-ne v1, v2, :cond_0

    iget-object v0, v0, Llyiahf/vczjk/ro4;->OooOoO0:Llyiahf/vczjk/ro4;

    goto :goto_0

    :cond_0
    return-object v0
.end method

.method public final OooOo0o()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    iget v0, v0, Llyiahf/vczjk/kf5;->OooOo0:I

    return v0
.end method

.method public final OooOoO()Llyiahf/vczjk/ws5;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooooOO()V

    iget v0, p0, Llyiahf/vczjk/ro4;->OooOo0:I

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OooOo0O:Llyiahf/vczjk/era;

    iget-object v0, v0, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ws5;

    return-object v0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/ro4;->OooOo0o:Llyiahf/vczjk/ws5;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    return-object v0
.end method

.method public final OooOoO0()Llyiahf/vczjk/ws5;
    .locals 3

    iget-boolean v0, p0, Llyiahf/vczjk/ro4;->Oooo00o:Z

    iget-object v1, p0, Llyiahf/vczjk/ro4;->Oooo00O:Llyiahf/vczjk/ws5;

    if-eqz v0, :cond_0

    invoke-virtual {v1}, Llyiahf/vczjk/ws5;->OooO0oO()V

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooOoO()Llyiahf/vczjk/ws5;

    move-result-object v0

    iget v2, v1, Llyiahf/vczjk/ws5;->OooOOOO:I

    invoke-virtual {v1, v2, v0}, Llyiahf/vczjk/ws5;->OooO0Oo(ILlyiahf/vczjk/ws5;)V

    sget-object v0, Llyiahf/vczjk/ro4;->OooooOO:Llyiahf/vczjk/qw;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/ws5;->OooOOO(Ljava/util/Comparator;)V

    const/4 v0, 0x0

    iput-boolean v0, p0, Llyiahf/vczjk/ro4;->Oooo00o:Z

    :cond_0
    return-object v1
.end method

.method public final OooOoOO(JLlyiahf/vczjk/eo3;IZ)V
    .locals 10

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v1, v0, Llyiahf/vczjk/jb0;->OooO0Oo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/v16;

    sget-object v2, Llyiahf/vczjk/v16;->OoooOO0:Llyiahf/vczjk/ft7;

    invoke-virtual {v1, p1, p2}, Llyiahf/vczjk/v16;->o0000oo(J)J

    move-result-wide v5

    iget-object p1, v0, Llyiahf/vczjk/jb0;->OooO0Oo:Ljava/lang/Object;

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/v16;

    sget-object v4, Llyiahf/vczjk/v16;->OoooOOo:Llyiahf/vczjk/qp3;

    move-object v7, p3

    move v8, p4

    move v9, p5

    invoke-virtual/range {v3 .. v9}, Llyiahf/vczjk/v16;->o0000OOo(Llyiahf/vczjk/o16;JLlyiahf/vczjk/eo3;IZ)V

    return-void
.end method

.method public final OooOoo()V
    .locals 4

    iget-boolean v0, p0, Llyiahf/vczjk/ro4;->o000oOoO:Z

    if-eqz v0, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v1, v0, Llyiahf/vczjk/jb0;->OooO0OO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/b04;

    iget-object v0, v0, Llyiahf/vczjk/jb0;->OooO0Oo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/v16;

    iget-object v0, v0, Llyiahf/vczjk/v16;->OooOoOO:Llyiahf/vczjk/v16;

    const/4 v2, 0x0

    iput-object v2, p0, Llyiahf/vczjk/ro4;->OoooOO0:Llyiahf/vczjk/v16;

    :goto_0
    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_3

    if-eqz v1, :cond_0

    iget-object v3, v1, Llyiahf/vczjk/v16;->OoooO0O:Llyiahf/vczjk/sg6;

    goto :goto_1

    :cond_0
    move-object v3, v2

    :goto_1
    if-eqz v3, :cond_1

    iput-object v1, p0, Llyiahf/vczjk/ro4;->OoooOO0:Llyiahf/vczjk/v16;

    goto :goto_2

    :cond_1
    if-eqz v1, :cond_2

    iget-object v1, v1, Llyiahf/vczjk/v16;->OooOoOO:Llyiahf/vczjk/v16;

    goto :goto_0

    :cond_2
    move-object v1, v2

    goto :goto_0

    :cond_3
    :goto_2
    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooOO0:Llyiahf/vczjk/v16;

    if-eqz v0, :cond_5

    iget-object v1, v0, Llyiahf/vczjk/v16;->OoooO0O:Llyiahf/vczjk/sg6;

    if-eqz v1, :cond_4

    goto :goto_3

    :cond_4
    const-string v0, "layer was not set"

    invoke-static {v0}, Llyiahf/vczjk/ix8;->OooOOOo(Ljava/lang/String;)Llyiahf/vczjk/k61;

    move-result-object v0

    throw v0

    :cond_5
    :goto_3
    if-eqz v0, :cond_6

    invoke-virtual {v0}, Llyiahf/vczjk/v16;->o0000Oo()V

    return-void

    :cond_6
    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v0

    if-eqz v0, :cond_7

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOoo()V

    :cond_7
    return-void
.end method

.method public final OooOoo0(ILlyiahf/vczjk/ro4;)V
    .locals 2

    iget-object v0, p2, Llyiahf/vczjk/ro4;->OooOoO0:Llyiahf/vczjk/ro4;

    if-eqz v0, :cond_1

    iget-object v0, p2, Llyiahf/vczjk/ro4;->OooOoO:Llyiahf/vczjk/xa;

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-direct {p0, p2}, Llyiahf/vczjk/ro4;->OooOO0O(Llyiahf/vczjk/ro4;)Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_1
    :goto_0
    iput-object p0, p2, Llyiahf/vczjk/ro4;->OooOoO0:Llyiahf/vczjk/ro4;

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OooOo0O:Llyiahf/vczjk/era;

    iget-object v1, v0, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ws5;

    invoke-virtual {v1, p1, p2}, Llyiahf/vczjk/ws5;->OooO00o(ILjava/lang/Object;)V

    iget-object p1, v0, Llyiahf/vczjk/era;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/po4;

    invoke-virtual {p1}, Llyiahf/vczjk/po4;->OooO00o()Ljava/lang/Object;

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->Oooo0oO()V

    iget-boolean p1, p2, Llyiahf/vczjk/ro4;->OooOOO0:Z

    if-eqz p1, :cond_2

    iget p1, p0, Llyiahf/vczjk/ro4;->OooOo0:I

    add-int/lit8 p1, p1, 0x1

    iput p1, p0, Llyiahf/vczjk/ro4;->OooOo0:I

    :cond_2
    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->Oooo00O()V

    iget-object p1, p0, Llyiahf/vczjk/ro4;->OooOoO:Llyiahf/vczjk/xa;

    if-eqz p1, :cond_3

    invoke-virtual {p2, p1}, Llyiahf/vczjk/ro4;->OooO0Oo(Llyiahf/vczjk/xa;)V

    :cond_3
    iget-object p1, p2, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget p1, p1, Llyiahf/vczjk/vo4;->OooOO0o:I

    if-lez p1, :cond_4

    iget-object p1, p0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget p2, p1, Llyiahf/vczjk/vo4;->OooOO0o:I

    add-int/lit8 p2, p2, 0x1

    invoke-virtual {p1, p2}, Llyiahf/vczjk/vo4;->OooO0OO(I)V

    :cond_4
    return-void
.end method

.method public final OooOooO()V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v1, v0, Llyiahf/vczjk/jb0;->OooO0Oo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/v16;

    iget-object v2, v0, Llyiahf/vczjk/jb0;->OooO0OO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/b04;

    :goto_0
    if-eq v1, v2, :cond_1

    const-string v3, "null cannot be cast to non-null type androidx.compose.ui.node.LayoutModifierNodeCoordinator"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v3, v1

    check-cast v3, Llyiahf/vczjk/io4;

    iget-object v3, v3, Llyiahf/vczjk/v16;->OoooO0O:Llyiahf/vczjk/sg6;

    if-eqz v3, :cond_0

    invoke-interface {v3}, Llyiahf/vczjk/sg6;->invalidate()V

    :cond_0
    iget-object v1, v1, Llyiahf/vczjk/v16;->OooOoO:Llyiahf/vczjk/v16;

    goto :goto_0

    :cond_1
    iget-object v0, v0, Llyiahf/vczjk/jb0;->OooO0OO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/b04;

    iget-object v0, v0, Llyiahf/vczjk/v16;->OoooO0O:Llyiahf/vczjk/sg6;

    if-eqz v0, :cond_2

    invoke-interface {v0}, Llyiahf/vczjk/sg6;->invalidate()V

    :cond_2
    return-void
.end method

.method public final OooOooo()V
    .locals 3

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/ro4;->OooOOo:Z

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OooOo00:Llyiahf/vczjk/ro4;

    const/4 v1, 0x0

    const/4 v2, 0x7

    if-eqz v0, :cond_0

    invoke-static {p0, v1, v2}, Llyiahf/vczjk/ro4;->OoooOO0(Llyiahf/vczjk/ro4;ZI)V

    return-void

    :cond_0
    invoke-static {p0, v1, v2}, Llyiahf/vczjk/ro4;->OoooOOO(Llyiahf/vczjk/ro4;ZI)V

    return-void
.end method

.method public final Oooo0()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    iget-boolean v0, v0, Llyiahf/vczjk/kf5;->Oooo000:Z

    return v0
.end method

.method public final Oooo000()V
    .locals 5

    iget-boolean v0, p0, Llyiahf/vczjk/ro4;->Oooo000:Z

    if-eqz v0, :cond_0

    return-void

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/n16;->OooO00o:Llyiahf/vczjk/l16;

    iget-object v0, v0, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    const/4 v1, 0x1

    if-eqz v0, :cond_1

    goto :goto_0

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooOOo:Llyiahf/vczjk/kl5;

    if-eqz v0, :cond_2

    :goto_0
    iput-boolean v1, p0, Llyiahf/vczjk/ro4;->OooOooO:Z

    return-void

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/ro4;->OooOooo:Llyiahf/vczjk/je8;

    iput-boolean v1, p0, Llyiahf/vczjk/ro4;->Oooo000:Z

    new-instance v1, Llyiahf/vczjk/hl7;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    new-instance v2, Llyiahf/vczjk/je8;

    invoke-direct {v2}, Llyiahf/vczjk/je8;-><init>()V

    iput-object v2, v1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    invoke-static {p0}, Llyiahf/vczjk/uo4;->OooO00o(Llyiahf/vczjk/ro4;)Llyiahf/vczjk/tg6;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/xa;

    invoke-virtual {v2}, Llyiahf/vczjk/xa;->getSnapshotObserver()Llyiahf/vczjk/vg6;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/qo4;

    invoke-direct {v3, p0, v1}, Llyiahf/vczjk/qo4;-><init>(Llyiahf/vczjk/ro4;Llyiahf/vczjk/hl7;)V

    iget-object v4, v2, Llyiahf/vczjk/vg6;->OooO0Oo:Llyiahf/vczjk/k65;

    invoke-virtual {v2, p0, v4, v3}, Llyiahf/vczjk/vg6;->OooO00o(Llyiahf/vczjk/ug6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;)V

    const/4 v2, 0x0

    iput-boolean v2, p0, Llyiahf/vczjk/ro4;->Oooo000:Z

    iget-object v1, v1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/je8;

    iput-object v1, p0, Llyiahf/vczjk/ro4;->OooOooo:Llyiahf/vczjk/je8;

    iput-boolean v2, p0, Llyiahf/vczjk/ro4;->OooOooO:Z

    invoke-static {p0}, Llyiahf/vczjk/uo4;->OooO00o(Llyiahf/vczjk/ro4;)Llyiahf/vczjk/tg6;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/xa;

    invoke-virtual {v1}, Llyiahf/vczjk/xa;->getSemanticsOwner()Llyiahf/vczjk/ue8;

    move-result-object v2

    invoke-virtual {v2, p0, v0}, Llyiahf/vczjk/ue8;->OooO0O0(Llyiahf/vczjk/ro4;Llyiahf/vczjk/je8;)V

    invoke-virtual {v1}, Llyiahf/vczjk/xa;->OooOooO()V

    return-void
.end method

.method public final Oooo00O()V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/ro4;->OooOo0:I

    if-lez v0, :cond_0

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/ro4;->OooOo:Z

    :cond_0
    iget-boolean v0, p0, Llyiahf/vczjk/ro4;->OooOOO0:Z

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OooOoO0:Llyiahf/vczjk/ro4;

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->Oooo00O()V

    :cond_1
    return-void
.end method

.method public final Oooo00o()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OooOoO:Llyiahf/vczjk/xa;

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final Oooo0O0()Ljava/lang/Boolean;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/w65;->Oooo0o0()Z

    move-result v0

    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    return-object v0

    :cond_0
    const/4 v0, 0x0

    return-object v0
.end method

.method public final Oooo0OO()V
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/ro4;->Oooo0oo:Llyiahf/vczjk/no4;

    sget-object v1, Llyiahf/vczjk/no4;->OooOOOO:Llyiahf/vczjk/no4;

    if-ne v0, v1, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooO0o()V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    const/4 v1, 0x1

    const/4 v2, 0x0

    :try_start_0
    iput-boolean v1, v0, Llyiahf/vczjk/w65;->OooOOoo:Z

    iget-boolean v1, v0, Llyiahf/vczjk/w65;->OooOo:Z

    if-nez v1, :cond_1

    const-string v1, "replace() called on item that was not placed"

    invoke-static {v1}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    goto :goto_0

    :catchall_0
    move-exception v1

    goto :goto_1

    :cond_1
    :goto_0
    iput-boolean v2, v0, Llyiahf/vczjk/w65;->Oooo0OO:Z

    invoke-virtual {v0}, Llyiahf/vczjk/w65;->Oooo0o0()Z

    move-result v1

    iget-wide v3, v0, Llyiahf/vczjk/w65;->OooOoOO:J

    iget-object v5, v0, Llyiahf/vczjk/w65;->OooOoo0:Llyiahf/vczjk/oe3;

    iget-object v6, v0, Llyiahf/vczjk/w65;->OooOoo:Llyiahf/vczjk/kj3;

    invoke-virtual {v0, v3, v4, v5, v6}, Llyiahf/vczjk/w65;->oo0o0Oo(JLlyiahf/vczjk/oe3;Llyiahf/vczjk/kj3;)V

    if-eqz v1, :cond_2

    iget-boolean v1, v0, Llyiahf/vczjk/w65;->Oooo0OO:Z

    if-nez v1, :cond_2

    iget-object v1, v0, Llyiahf/vczjk/w65;->OooOOo:Llyiahf/vczjk/vo4;

    iget-object v1, v1, Llyiahf/vczjk/vo4;->OooO00o:Llyiahf/vczjk/ro4;

    invoke-virtual {v1}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v1

    if-eqz v1, :cond_2

    invoke-virtual {v1, v2}, Llyiahf/vczjk/ro4;->OoooO(Z)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :cond_2
    iput-boolean v2, v0, Llyiahf/vczjk/w65;->OooOOoo:Z

    return-void

    :goto_1
    iput-boolean v2, v0, Llyiahf/vczjk/w65;->OooOOoo:Z

    throw v1
.end method

.method public final Oooo0o(Llyiahf/vczjk/ro4;)V
    .locals 4

    iget-object v0, p1, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget v0, v0, Llyiahf/vczjk/vo4;->OooOO0o:I

    if-lez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget v1, v0, Llyiahf/vczjk/vo4;->OooOO0o:I

    add-int/lit8 v1, v1, -0x1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/vo4;->OooO0OO(I)V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/ro4;->OooOoO:Llyiahf/vczjk/xa;

    if-eqz v0, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/ro4;->OooO0oo()V

    :cond_1
    const/4 v0, 0x0

    iput-object v0, p1, Llyiahf/vczjk/ro4;->OooOoO0:Llyiahf/vczjk/ro4;

    iget-object v1, p1, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v1, v1, Llyiahf/vczjk/jb0;->OooO0Oo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/v16;

    iput-object v0, v1, Llyiahf/vczjk/v16;->OooOoOO:Llyiahf/vczjk/v16;

    iget-boolean v1, p1, Llyiahf/vczjk/ro4;->OooOOO0:Z

    if-eqz v1, :cond_2

    iget v1, p0, Llyiahf/vczjk/ro4;->OooOo0:I

    add-int/lit8 v1, v1, -0x1

    iput v1, p0, Llyiahf/vczjk/ro4;->OooOo0:I

    iget-object p1, p1, Llyiahf/vczjk/ro4;->OooOo0O:Llyiahf/vczjk/era;

    iget-object p1, p1, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/ws5;

    iget-object v1, p1, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget p1, p1, Llyiahf/vczjk/ws5;->OooOOOO:I

    const/4 v2, 0x0

    :goto_0
    if-ge v2, p1, :cond_2

    aget-object v3, v1, v2

    check-cast v3, Llyiahf/vczjk/ro4;

    iget-object v3, v3, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v3, v3, Llyiahf/vczjk/jb0;->OooO0Oo:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/v16;

    iput-object v0, v3, Llyiahf/vczjk/v16;->OooOoOO:Llyiahf/vczjk/v16;

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_2
    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->Oooo00O()V

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->Oooo0oO()V

    return-void
.end method

.method public final Oooo0o0(III)V
    .locals 5

    if-ne p1, p2, :cond_0

    return-void

    :cond_0
    const/4 v0, 0x0

    :goto_0
    if-ge v0, p3, :cond_3

    if-le p1, p2, :cond_1

    add-int v1, p1, v0

    goto :goto_1

    :cond_1
    move v1, p1

    :goto_1
    if-le p1, p2, :cond_2

    add-int v2, p2, v0

    goto :goto_2

    :cond_2
    add-int v2, p2, p3

    add-int/lit8 v2, v2, -0x2

    :goto_2
    iget-object v3, p0, Llyiahf/vczjk/ro4;->OooOo0O:Llyiahf/vczjk/era;

    iget-object v4, v3, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/ws5;

    invoke-virtual {v4, v1}, Llyiahf/vczjk/ws5;->OooOO0O(I)Ljava/lang/Object;

    move-result-object v1

    iget-object v4, v3, Llyiahf/vczjk/era;->OooOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/po4;

    invoke-virtual {v4}, Llyiahf/vczjk/po4;->OooO00o()Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ro4;

    iget-object v3, v3, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/ws5;

    invoke-virtual {v3, v2, v1}, Llyiahf/vczjk/ws5;->OooO00o(ILjava/lang/Object;)V

    invoke-virtual {v4}, Llyiahf/vczjk/po4;->OooO00o()Ljava/lang/Object;

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_3
    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->Oooo0oO()V

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->Oooo00O()V

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooOooo()V

    return-void
.end method

.method public final Oooo0oO()V
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/ro4;->OooOOO0:Z

    if-eqz v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->Oooo0oO()V

    :cond_0
    return-void

    :cond_1
    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/ro4;->Oooo00o:Z

    return-void
.end method

.method public final Oooo0oo(Llyiahf/vczjk/rk1;)Z
    .locals 3

    if-eqz p1, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/ro4;->Oooo0oo:Llyiahf/vczjk/no4;

    sget-object v1, Llyiahf/vczjk/no4;->OooOOOO:Llyiahf/vczjk/no4;

    if-ne v0, v1, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooO0o0()V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    iget-wide v1, p1, Llyiahf/vczjk/rk1;->OooO00o:J

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/kf5;->o000000(J)Z

    move-result p1

    return p1

    :cond_1
    const/4 p1, 0x0

    return p1
.end method

.method public final OoooO(Z)V
    .locals 2

    iget-boolean v0, p0, Llyiahf/vczjk/ro4;->OooOOO0:Z

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OooOoO:Llyiahf/vczjk/xa;

    if-eqz v0, :cond_0

    const/4 v1, 0x1

    invoke-virtual {v0, p0, v1, p1}, Llyiahf/vczjk/xa;->OooOoo(Llyiahf/vczjk/ro4;ZZ)V

    :cond_0
    return-void
.end method

.method public final OoooO0(II)V
    .locals 2

    if-ltz p2, :cond_0

    goto :goto_0

    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "count ("

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, ") must be greater than 0"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO00o(Ljava/lang/String;)V

    :goto_0
    add-int/2addr p2, p1

    add-int/lit8 p2, p2, -0x1

    if-gt p1, p2, :cond_1

    :goto_1
    iget-object v0, p0, Llyiahf/vczjk/ro4;->OooOo0O:Llyiahf/vczjk/era;

    iget-object v1, v0, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ws5;

    iget-object v1, v1, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    aget-object v1, v1, p2

    check-cast v1, Llyiahf/vczjk/ro4;

    invoke-virtual {p0, v1}, Llyiahf/vczjk/ro4;->Oooo0o(Llyiahf/vczjk/ro4;)V

    iget-object v1, v0, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ws5;

    invoke-virtual {v1, p2}, Llyiahf/vczjk/ws5;->OooOO0O(I)Ljava/lang/Object;

    move-result-object v1

    iget-object v0, v0, Llyiahf/vczjk/era;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/po4;

    invoke-virtual {v0}, Llyiahf/vczjk/po4;->OooO00o()Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ro4;

    if-eq p2, p1, :cond_1

    add-int/lit8 p2, p2, -0x1

    goto :goto_1

    :cond_1
    return-void
.end method

.method public final OoooO00()V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OooOo0O:Llyiahf/vczjk/era;

    iget-object v1, v0, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ws5;

    iget v1, v1, Llyiahf/vczjk/ws5;->OooOOOO:I

    add-int/lit8 v1, v1, -0x1

    :goto_0
    const/4 v2, -0x1

    iget-object v3, v0, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/ws5;

    if-ge v2, v1, :cond_0

    iget-object v2, v3, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    aget-object v2, v2, v1

    check-cast v2, Llyiahf/vczjk/ro4;

    invoke-virtual {p0, v2}, Llyiahf/vczjk/ro4;->Oooo0o(Llyiahf/vczjk/ro4;)V

    add-int/lit8 v1, v1, -0x1

    goto :goto_0

    :cond_0
    invoke-virtual {v3}, Llyiahf/vczjk/ws5;->OooO0oO()V

    iget-object v0, v0, Llyiahf/vczjk/era;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/po4;

    invoke-virtual {v0}, Llyiahf/vczjk/po4;->OooO00o()Ljava/lang/Object;

    return-void
.end method

.method public final OoooO0O()V
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/ro4;->Oooo0oo:Llyiahf/vczjk/no4;

    sget-object v1, Llyiahf/vczjk/no4;->OooOOOO:Llyiahf/vczjk/no4;

    if-ne v0, v1, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooO0o()V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v1, v0, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v0, 0x1

    const/4 v7, 0x0

    :try_start_0
    iput-boolean v0, v1, Llyiahf/vczjk/kf5;->OooOOoo:Z

    iget-boolean v0, v1, Llyiahf/vczjk/kf5;->OooOo0o:Z

    if-nez v0, :cond_1

    const-string v0, "replace called on unplaced item"

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    goto :goto_0

    :catchall_0
    move-exception v0

    goto :goto_1

    :cond_1
    :goto_0
    iget-boolean v0, v1, Llyiahf/vczjk/kf5;->Oooo000:Z

    iget-wide v2, v1, Llyiahf/vczjk/kf5;->OooOoO:J

    iget v4, v1, Llyiahf/vczjk/kf5;->OooOoo:F

    iget-object v5, v1, Llyiahf/vczjk/kf5;->OooOoOO:Llyiahf/vczjk/oe3;

    iget-object v6, v1, Llyiahf/vczjk/kf5;->OooOoo0:Llyiahf/vczjk/kj3;

    invoke-virtual/range {v1 .. v6}, Llyiahf/vczjk/kf5;->o0O0O00(JFLlyiahf/vczjk/oe3;Llyiahf/vczjk/kj3;)V

    if-eqz v0, :cond_2

    iget-boolean v0, v1, Llyiahf/vczjk/kf5;->OoooO0O:Z

    if-nez v0, :cond_2

    iget-object v0, v1, Llyiahf/vczjk/kf5;->OooOOo:Llyiahf/vczjk/vo4;

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooO00o:Llyiahf/vczjk/ro4;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v0

    if-eqz v0, :cond_2

    invoke-virtual {v0, v7}, Llyiahf/vczjk/ro4;->o000oOoO(Z)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :cond_2
    iput-boolean v7, v1, Llyiahf/vczjk/kf5;->OooOOoo:Z

    return-void

    :goto_1
    iput-boolean v7, v1, Llyiahf/vczjk/kf5;->OooOOoo:Z

    throw v0
.end method

.method public final OoooOo0()V
    .locals 6

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooOoO()Llyiahf/vczjk/ws5;

    move-result-object v0

    iget-object v1, v0, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v0, v0, Llyiahf/vczjk/ws5;->OooOOOO:I

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v0, :cond_1

    aget-object v3, v1, v2

    check-cast v3, Llyiahf/vczjk/ro4;

    iget-object v4, v3, Llyiahf/vczjk/ro4;->Oooo:Llyiahf/vczjk/no4;

    iput-object v4, v3, Llyiahf/vczjk/ro4;->Oooo0oo:Llyiahf/vczjk/no4;

    sget-object v5, Llyiahf/vczjk/no4;->OooOOOO:Llyiahf/vczjk/no4;

    if-eq v4, v5, :cond_0

    invoke-virtual {v3}, Llyiahf/vczjk/ro4;->OoooOo0()V

    :cond_0
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_1
    return-void
.end method

.method public final OoooOoO(Llyiahf/vczjk/f62;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ro4;->Oooo0OO:Llyiahf/vczjk/f62;

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_1

    iput-object p1, p0, Llyiahf/vczjk/ro4;->Oooo0OO:Llyiahf/vczjk/f62;

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooOooo()V

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object p1

    if-eqz p1, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/ro4;->OooOoo()V

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooOooO()V

    iget-object p1, p0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object p1, p1, Llyiahf/vczjk/jb0;->OooO0o:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/jl5;

    :goto_0
    if-eqz p1, :cond_1

    invoke-interface {p1}, Llyiahf/vczjk/l52;->OooO0Oo()V

    iget-object p1, p1, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_0

    :cond_1
    return-void
.end method

.method public final OoooOoo(Llyiahf/vczjk/ro4;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OooOo00:Llyiahf/vczjk/ro4;

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_3

    iput-object p1, p0, Llyiahf/vczjk/ro4;->OooOo00:Llyiahf/vczjk/ro4;

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    if-eqz p1, :cond_1

    iget-object p1, v0, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    if-nez p1, :cond_0

    new-instance p1, Llyiahf/vczjk/w65;

    invoke-direct {p1, v0}, Llyiahf/vczjk/w65;-><init>(Llyiahf/vczjk/vo4;)V

    iput-object p1, v0, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v0, p1, Llyiahf/vczjk/jb0;->OooO0Oo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/v16;

    iget-object p1, p1, Llyiahf/vczjk/jb0;->OooO0OO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/b04;

    iget-object p1, p1, Llyiahf/vczjk/v16;->OooOoO:Llyiahf/vczjk/v16;

    :goto_0
    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_2

    if-eqz v0, :cond_2

    invoke-virtual {v0}, Llyiahf/vczjk/v16;->o0000()V

    iget-object v0, v0, Llyiahf/vczjk/v16;->OooOoO:Llyiahf/vczjk/v16;

    goto :goto_0

    :cond_1
    const/4 p1, 0x0

    iput-object p1, v0, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    :cond_2
    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooOooo()V

    :cond_3
    return-void
.end method

.method public final Ooooo00(Llyiahf/vczjk/lf5;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ro4;->Oooo0:Llyiahf/vczjk/lf5;

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_1

    iput-object p1, p0, Llyiahf/vczjk/ro4;->Oooo0:Llyiahf/vczjk/lf5;

    iget-object v0, p0, Llyiahf/vczjk/ro4;->Oooo0O0:Llyiahf/vczjk/era;

    if-eqz v0, :cond_0

    iget-object v0, v0, Llyiahf/vczjk/era;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooOooo()V

    :cond_1
    return-void
.end method

.method public final Ooooo0o(Llyiahf/vczjk/kl5;)V
    .locals 2

    iget-boolean v0, p0, Llyiahf/vczjk/ro4;->OooOOO0:Z

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooOOO:Llyiahf/vczjk/kl5;

    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    if-ne v0, v1, :cond_0

    goto :goto_0

    :cond_0
    const-string v0, "Modifiers are not supported on virtual LayoutNodes"

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO00o(Ljava/lang/String;)V

    :cond_1
    :goto_0
    iget-boolean v0, p0, Llyiahf/vczjk/ro4;->Ooooo00:Z

    if-eqz v0, :cond_2

    const-string v0, "modifier is updated when deactivated"

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO00o(Ljava/lang/String;)V

    :cond_2
    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->Oooo00o()Z

    move-result v0

    if-eqz v0, :cond_4

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ro4;->OooO0OO(Llyiahf/vczjk/kl5;)V

    iget-boolean p1, p0, Llyiahf/vczjk/ro4;->OooOooO:Z

    if-eqz p1, :cond_3

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->Oooo000()V

    :cond_3
    return-void

    :cond_4
    iput-object p1, p0, Llyiahf/vczjk/ro4;->OoooOOo:Llyiahf/vczjk/kl5;

    return-void
.end method

.method public final OooooO0(Llyiahf/vczjk/gga;)V
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/ro4;->Oooo0o:Llyiahf/vczjk/gga;

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_8

    iput-object p1, p0, Llyiahf/vczjk/ro4;->Oooo0o:Llyiahf/vczjk/gga;

    iget-object p1, p0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object p1, p1, Llyiahf/vczjk/jb0;->OooO0o:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/jl5;

    iget v0, p1, Llyiahf/vczjk/jl5;->OooOOOo:I

    const/16 v1, 0x10

    and-int/2addr v0, v1

    if-eqz v0, :cond_8

    :goto_0
    if-eqz p1, :cond_8

    iget v0, p1, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/2addr v0, v1

    if-eqz v0, :cond_7

    const/4 v0, 0x0

    move-object v2, p1

    move-object v3, v0

    :goto_1
    if-eqz v2, :cond_7

    instance-of v4, v2, Llyiahf/vczjk/ny6;

    if-eqz v4, :cond_0

    check-cast v2, Llyiahf/vczjk/ny6;

    invoke-interface {v2}, Llyiahf/vczjk/ny6;->o00oO0O()V

    goto :goto_4

    :cond_0
    iget v4, v2, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/2addr v4, v1

    if-eqz v4, :cond_6

    instance-of v4, v2, Llyiahf/vczjk/m52;

    if-eqz v4, :cond_6

    move-object v4, v2

    check-cast v4, Llyiahf/vczjk/m52;

    iget-object v4, v4, Llyiahf/vczjk/m52;->OooOoo0:Llyiahf/vczjk/jl5;

    const/4 v5, 0x0

    :goto_2
    const/4 v6, 0x1

    if-eqz v4, :cond_5

    iget v7, v4, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/2addr v7, v1

    if-eqz v7, :cond_4

    add-int/lit8 v5, v5, 0x1

    if-ne v5, v6, :cond_1

    move-object v2, v4

    goto :goto_3

    :cond_1
    if-nez v3, :cond_2

    new-instance v3, Llyiahf/vczjk/ws5;

    new-array v6, v1, [Llyiahf/vczjk/jl5;

    invoke-direct {v3, v6}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    :cond_2
    if-eqz v2, :cond_3

    invoke-virtual {v3, v2}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    move-object v2, v0

    :cond_3
    invoke-virtual {v3, v4}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :cond_4
    :goto_3
    iget-object v4, v4, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_2

    :cond_5
    if-ne v5, v6, :cond_6

    goto :goto_1

    :cond_6
    :goto_4
    invoke-static {v3}, Llyiahf/vczjk/yi4;->OooOo0(Llyiahf/vczjk/ws5;)Llyiahf/vczjk/jl5;

    move-result-object v2

    goto :goto_1

    :cond_7
    iget v0, p1, Llyiahf/vczjk/jl5;->OooOOOo:I

    and-int/2addr v0, v1

    if-eqz v0, :cond_8

    iget-object p1, p1, Llyiahf/vczjk/jl5;->OooOOo:Llyiahf/vczjk/jl5;

    goto :goto_0

    :cond_8
    return-void
.end method

.method public final OooooOO()V
    .locals 6

    iget v0, p0, Llyiahf/vczjk/ro4;->OooOo0:I

    if-lez v0, :cond_3

    iget-boolean v0, p0, Llyiahf/vczjk/ro4;->OooOo:Z

    if-eqz v0, :cond_3

    const/4 v0, 0x0

    iput-boolean v0, p0, Llyiahf/vczjk/ro4;->OooOo:Z

    iget-object v1, p0, Llyiahf/vczjk/ro4;->OooOo0o:Llyiahf/vczjk/ws5;

    if-nez v1, :cond_0

    new-instance v1, Llyiahf/vczjk/ws5;

    const/16 v2, 0x10

    new-array v2, v2, [Llyiahf/vczjk/ro4;

    invoke-direct {v1, v2}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    iput-object v1, p0, Llyiahf/vczjk/ro4;->OooOo0o:Llyiahf/vczjk/ws5;

    :cond_0
    invoke-virtual {v1}, Llyiahf/vczjk/ws5;->OooO0oO()V

    iget-object v2, p0, Llyiahf/vczjk/ro4;->OooOo0O:Llyiahf/vczjk/era;

    iget-object v2, v2, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/ws5;

    iget-object v3, v2, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v2, v2, Llyiahf/vczjk/ws5;->OooOOOO:I

    :goto_0
    if-ge v0, v2, :cond_2

    aget-object v4, v3, v0

    check-cast v4, Llyiahf/vczjk/ro4;

    iget-boolean v5, v4, Llyiahf/vczjk/ro4;->OooOOO0:Z

    if-eqz v5, :cond_1

    invoke-virtual {v4}, Llyiahf/vczjk/ro4;->OooOoO()Llyiahf/vczjk/ws5;

    move-result-object v4

    iget v5, v1, Llyiahf/vczjk/ws5;->OooOOOO:I

    invoke-virtual {v1, v5, v4}, Llyiahf/vczjk/ws5;->OooO0Oo(ILlyiahf/vczjk/ws5;)V

    goto :goto_1

    :cond_1
    invoke-virtual {v1, v4}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :goto_1
    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v1, v0, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    const/4 v2, 0x1

    iput-boolean v2, v1, Llyiahf/vczjk/kf5;->Oooo0o:Z

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    if-eqz v0, :cond_3

    iput-boolean v2, v0, Llyiahf/vczjk/w65;->Oooo00O:Z

    :cond_3
    return-void
.end method

.method public final o000oOoO(Z)V
    .locals 2

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/ro4;->OooOOo:Z

    iget-boolean v0, p0, Llyiahf/vczjk/ro4;->OooOOO0:Z

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/ro4;->OooOoO:Llyiahf/vczjk/xa;

    if-eqz v0, :cond_0

    const/4 v1, 0x0

    invoke-virtual {v0, p0, v1, p1}, Llyiahf/vczjk/xa;->OooOoo(Llyiahf/vczjk/ro4;ZZ)V

    :cond_0
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-static {p0}, Llyiahf/vczjk/sb;->OoooO0O(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, " children: "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Llyiahf/vczjk/ro4;->OooOOOO()Ljava/util/List;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ts5;

    iget-object v1, v1, Llyiahf/vczjk/ts5;->OooOOO0:Llyiahf/vczjk/ws5;

    iget v1, v1, Llyiahf/vczjk/ws5;->OooOOOO:I

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, " measurePolicy: "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/ro4;->Oooo0:Llyiahf/vczjk/lf5;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
