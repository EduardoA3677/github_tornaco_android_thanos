.class public final synthetic Llyiahf/vczjk/ska;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/bla;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/bla;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/ska;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/ska;->OooOOO:Llyiahf/vczjk/bla;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 11

    iget v0, p0, Llyiahf/vczjk/ska;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/ska;->OooOOO:Llyiahf/vczjk/bla;

    iget-object v0, v0, Llyiahf/vczjk/bla;->OooO0o0:Landroid/content/Context;

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/ska;->OooOOO:Llyiahf/vczjk/bla;

    iget-object v1, v0, Llyiahf/vczjk/bla;->OooO0o:Llyiahf/vczjk/s29;

    invoke-virtual {v1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v2

    move-object v3, v2

    check-cast v3, Llyiahf/vczjk/td0;

    invoke-virtual {v1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/td0;

    iget-boolean v2, v2, Llyiahf/vczjk/td0;->OooO0o:Z

    xor-int/lit8 v9, v2, 0x1

    const/4 v6, 0x0

    const/16 v10, 0x1f

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    invoke-static/range {v3 .. v10}, Llyiahf/vczjk/td0;->OooO00o(Llyiahf/vczjk/td0;ZZLjava/util/List;Ljava/util/List;Llyiahf/vczjk/nw;ZI)Llyiahf/vczjk/td0;

    move-result-object v2

    const/4 v3, 0x0

    invoke-virtual {v1, v3, v2}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    invoke-virtual {v0}, Llyiahf/vczjk/bla;->OooOO0o()V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/ska;->OooOOO:Llyiahf/vczjk/bla;

    invoke-virtual {v0}, Llyiahf/vczjk/bla;->OooOO0o()V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
