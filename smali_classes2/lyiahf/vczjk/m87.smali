.class public final synthetic Llyiahf/vczjk/m87;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Z

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(IZ)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Llyiahf/vczjk/m87;->OooOOO0:I

    iput-boolean p2, p0, Llyiahf/vczjk/m87;->OooOOO:Z

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Lgithub/tornaco/android/thanos/core/profile/IRuleChangeListener;

    const-string v0, "it"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget v0, p0, Llyiahf/vczjk/m87;->OooOOO0:I

    iget-boolean v1, p0, Llyiahf/vczjk/m87;->OooOOO:Z

    invoke-interface {p1, v0, v1}, Lgithub/tornaco/android/thanos/core/profile/IRuleChangeListener;->onRuleEnabledStateChanged(IZ)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
