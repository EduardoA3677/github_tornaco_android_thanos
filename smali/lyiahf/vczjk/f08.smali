.class public final synthetic Llyiahf/vczjk/f08;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/wa5;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Landroid/content/Context;

.field public final synthetic OooOOOo:Llyiahf/vczjk/qs5;

.field public final synthetic OooOOo0:Llyiahf/vczjk/qs5;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/wa5;Landroid/content/Context;Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;I)V
    .locals 0

    iput p5, p0, Llyiahf/vczjk/f08;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/f08;->OooOOO:Llyiahf/vczjk/wa5;

    iput-object p2, p0, Llyiahf/vczjk/f08;->OooOOOO:Landroid/content/Context;

    iput-object p3, p0, Llyiahf/vczjk/f08;->OooOOOo:Llyiahf/vczjk/qs5;

    iput-object p4, p0, Llyiahf/vczjk/f08;->OooOOo0:Llyiahf/vczjk/qs5;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v1, p0, Llyiahf/vczjk/f08;->OooOOO:Llyiahf/vczjk/wa5;

    iget-object v2, p0, Llyiahf/vczjk/f08;->OooOOOO:Landroid/content/Context;

    iget-object v3, p0, Llyiahf/vczjk/f08;->OooOOo0:Llyiahf/vczjk/qs5;

    const/4 v4, 0x3

    iget-object v5, p0, Llyiahf/vczjk/f08;->OooOOOo:Llyiahf/vczjk/qs5;

    iget v6, p0, Llyiahf/vczjk/f08;->OooOOO0:I

    packed-switch v6, :pswitch_data_0

    invoke-interface {v5}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Ljava/util/List;

    invoke-interface {v6}, Ljava/util/List;->size()I

    move-result v6

    if-le v6, v4, :cond_0

    invoke-interface {v3}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/cm4;

    iget-boolean v3, v3, Llyiahf/vczjk/cm4;->OooO00o:Z

    if-nez v3, :cond_0

    sget-object v1, Llyiahf/vczjk/im4;->OooO00o:Llyiahf/vczjk/im4;

    invoke-virtual {v1}, Llyiahf/vczjk/im4;->OooO00o()V

    goto :goto_1

    :cond_0
    invoke-interface {v5}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/util/List;

    new-instance v4, Ljava/util/ArrayList;

    const/16 v5, 0xa

    invoke-static {v3, v5}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v5

    invoke-direct {v4, v5}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_1

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-static {v5}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->fromAppInfo(Lgithub/tornaco/android/thanos/core/pm/AppInfo;)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object v5

    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_1
    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    sget v4, Lgithub/tornaco/android/thanos/picker/AppPickerActivity;->o000oOoO:I

    new-instance v4, Landroid/content/Intent;

    const-class v5, Lgithub/tornaco/android/thanos/picker/AppPickerActivity;

    invoke-direct {v4, v2, v5}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    new-instance v2, Landroid/os/Bundle;

    invoke-direct {v2}, Landroid/os/Bundle;-><init>()V

    const-string v5, "github.tornaco.android.thanos.picker.extra.EXTRA_EXCLUDE_PKGS"

    invoke-virtual {v2, v5, v3}, Landroid/os/Bundle;->putParcelableArrayList(Ljava/lang/String;Ljava/util/ArrayList;)V

    invoke-virtual {v4, v2}, Landroid/content/Intent;->putExtras(Landroid/os/Bundle;)Landroid/content/Intent;

    invoke-virtual {v1, v4}, Llyiahf/vczjk/wa5;->OooO00o(Ljava/lang/Object;)V

    :goto_1
    return-object v0

    :pswitch_0
    invoke-interface {v5}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/cm4;

    iget-boolean v5, v5, Llyiahf/vczjk/cm4;->OooO00o:Z

    if-nez v5, :cond_3

    invoke-interface {v3}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/util/List;

    invoke-interface {v3}, Ljava/util/List;->size()I

    move-result v3

    if-ge v3, v4, :cond_2

    goto :goto_2

    :cond_2
    sget-object v1, Llyiahf/vczjk/im4;->OooO00o:Llyiahf/vczjk/im4;

    invoke-virtual {v1}, Llyiahf/vczjk/im4;->OooO00o()V

    goto :goto_3

    :cond_3
    :goto_2
    sget v3, Ltornaco/apps/thanox/picker/PkgPickerActivity;->OoooO0O:I

    const-string v3, "context"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v3, Landroid/content/Intent;

    const-class v4, Ltornaco/apps/thanox/picker/PkgPickerActivity;

    invoke-direct {v3, v2, v4}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    invoke-virtual {v1, v3}, Llyiahf/vczjk/wa5;->OooO00o(Ljava/lang/Object;)V

    :goto_3
    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
