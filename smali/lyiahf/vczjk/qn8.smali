.class public final synthetic Llyiahf/vczjk/qn8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ol1;


# instance fields
.field public final synthetic OooO00o:Llyiahf/vczjk/tn8;

.field public final synthetic OooO0O0:Landroid/app/Activity;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/tn8;Landroid/app/Activity;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/qn8;->OooO00o:Llyiahf/vczjk/tn8;

    iput-object p2, p0, Llyiahf/vczjk/qn8;->OooO0O0:Landroid/app/Activity;

    return-void
.end method


# virtual methods
.method public final accept(Ljava/lang/Object;)V
    .locals 2

    check-cast p1, Landroid/content/res/Configuration;

    iget-object p1, p0, Llyiahf/vczjk/qn8;->OooO00o:Llyiahf/vczjk/tn8;

    iget-object v0, p1, Llyiahf/vczjk/tn8;->OooO0o0:Llyiahf/vczjk/ed5;

    if-eqz v0, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/qn8;->OooO0O0:Landroid/app/Activity;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/tn8;->OooO00o(Landroid/app/Activity;)Llyiahf/vczjk/voa;

    move-result-object p1

    invoke-virtual {v0, v1, p1}, Llyiahf/vczjk/ed5;->Oooo00o(Landroid/app/Activity;Llyiahf/vczjk/voa;)V

    :cond_0
    return-void
.end method
