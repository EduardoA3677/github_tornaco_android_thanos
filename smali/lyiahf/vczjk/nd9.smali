.class public final Llyiahf/vczjk/nd9;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO0Oo:Ljava/lang/String;


# instance fields
.field public final OooO00o:Landroid/content/ComponentName;

.field public final OooO0O0:Llyiahf/vczjk/vp3;

.field public final OooO0OO:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const-string v0, "SystemJobInfoConverter"

    invoke-static {v0}, Llyiahf/vczjk/o55;->OooOOOO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/nd9;->OooO0Oo:Ljava/lang/String;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Llyiahf/vczjk/vp3;Z)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/nd9;->OooO0O0:Llyiahf/vczjk/vp3;

    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object p1

    new-instance p2, Landroid/content/ComponentName;

    const-class v0, Landroidx/work/impl/background/systemjob/SystemJobService;

    invoke-direct {p2, p1, v0}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    iput-object p2, p0, Llyiahf/vczjk/nd9;->OooO00o:Landroid/content/ComponentName;

    iput-boolean p3, p0, Llyiahf/vczjk/nd9;->OooO0OO:Z

    return-void
.end method
