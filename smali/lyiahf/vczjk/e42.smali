.class public final Llyiahf/vczjk/e42;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/e42;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/e42;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/e42;->OooO00o:Llyiahf/vczjk/e42;

    return-void
.end method


# virtual methods
.method public final OooO00o(Landroid/animation/AnimatorSet;)V
    .locals 1

    const-string v0, "animatorSet"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Landroid/animation/AnimatorSet;->reverse()V

    return-void
.end method

.method public final OooO0O0(Landroid/animation/AnimatorSet;J)V
    .locals 1

    const-string v0, "animatorSet"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1, p2, p3}, Landroid/animation/AnimatorSet;->setCurrentPlayTime(J)V

    return-void
.end method
