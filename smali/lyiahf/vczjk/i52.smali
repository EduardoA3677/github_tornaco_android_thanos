.class public final Llyiahf/vczjk/i52;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO0o0:Ljava/lang/String;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/xj3;

.field public final OooO0O0:Llyiahf/vczjk/sw7;

.field public final OooO0OO:Llyiahf/vczjk/vp3;

.field public final OooO0Oo:Ljava/util/HashMap;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const-string v0, "DelayedWorkTracker"

    invoke-static {v0}, Llyiahf/vczjk/o55;->OooOOOO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/i52;->OooO0o0:Ljava/lang/String;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/xj3;Llyiahf/vczjk/sw7;Llyiahf/vczjk/vp3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/i52;->OooO00o:Llyiahf/vczjk/xj3;

    iput-object p2, p0, Llyiahf/vczjk/i52;->OooO0O0:Llyiahf/vczjk/sw7;

    iput-object p3, p0, Llyiahf/vczjk/i52;->OooO0OO:Llyiahf/vczjk/vp3;

    new-instance p1, Ljava/util/HashMap;

    invoke-direct {p1}, Ljava/util/HashMap;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/i52;->OooO0Oo:Ljava/util/HashMap;

    return-void
.end method
