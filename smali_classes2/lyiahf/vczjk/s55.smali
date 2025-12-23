.class public final Llyiahf/vczjk/s55;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO0Oo:[Ljava/lang/String;

.field public static final OooO0o0:[Ljava/lang/String;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/to1;

.field public final OooO0O0:Llyiahf/vczjk/s29;

.field public OooO0OO:Llyiahf/vczjk/r09;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    const-string v0, "logcat"

    const-string v1, "-v"

    const-string v2, "uid"

    const-string v3, "epoch"

    filled-new-array {v0, v1, v2, v1, v3}, [Ljava/lang/String;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/s55;->OooO0Oo:[Ljava/lang/String;

    const-string v0, "-T"

    const-string v1, "1"

    filled-new-array {v0, v1}, [Ljava/lang/String;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/s55;->OooO0o0:[Ljava/lang/String;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/to1;)V
    .locals 1

    const-string v0, "scope"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/s55;->OooO00o:Llyiahf/vczjk/to1;

    const/4 p1, 0x0

    invoke-static {p1}, Llyiahf/vczjk/r02;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/s55;->OooO0O0:Llyiahf/vczjk/s29;

    return-void
.end method
