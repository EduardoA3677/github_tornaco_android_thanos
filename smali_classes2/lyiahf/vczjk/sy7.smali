.class public final synthetic Llyiahf/vczjk/sy7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/xr1;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Landroidx/appcompat/app/AppCompatActivity;

.field public final synthetic OooOOOo:Lnow/fortuitous/thanos/process/v2/RunningService;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/xr1;Landroidx/appcompat/app/AppCompatActivity;Lnow/fortuitous/thanos/process/v2/RunningService;I)V
    .locals 0

    iput p4, p0, Llyiahf/vczjk/sy7;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/sy7;->OooOOO:Llyiahf/vczjk/xr1;

    iput-object p2, p0, Llyiahf/vczjk/sy7;->OooOOOO:Landroidx/appcompat/app/AppCompatActivity;

    iput-object p3, p0, Llyiahf/vczjk/sy7;->OooOOOo:Lnow/fortuitous/thanos/process/v2/RunningService;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    iget v0, p0, Llyiahf/vczjk/sy7;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Llyiahf/vczjk/ez7;

    iget-object v1, p0, Llyiahf/vczjk/sy7;->OooOOOO:Landroidx/appcompat/app/AppCompatActivity;

    iget-object v2, p0, Llyiahf/vczjk/sy7;->OooOOOo:Lnow/fortuitous/thanos/process/v2/RunningService;

    const/4 v3, 0x0

    invoke-direct {v0, v1, v2, v3}, Llyiahf/vczjk/ez7;-><init>(Landroidx/appcompat/app/AppCompatActivity;Lnow/fortuitous/thanos/process/v2/RunningService;Llyiahf/vczjk/yo1;)V

    const/4 v1, 0x3

    iget-object v2, p0, Llyiahf/vczjk/sy7;->OooOOO:Llyiahf/vczjk/xr1;

    invoke-static {v2, v3, v3, v0, v1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/dz7;

    iget-object v1, p0, Llyiahf/vczjk/sy7;->OooOOOO:Landroidx/appcompat/app/AppCompatActivity;

    iget-object v2, p0, Llyiahf/vczjk/sy7;->OooOOOo:Lnow/fortuitous/thanos/process/v2/RunningService;

    const/4 v3, 0x0

    invoke-direct {v0, v1, v2, v3}, Llyiahf/vczjk/dz7;-><init>(Landroidx/appcompat/app/AppCompatActivity;Lnow/fortuitous/thanos/process/v2/RunningService;Llyiahf/vczjk/yo1;)V

    const/4 v1, 0x3

    iget-object v2, p0, Llyiahf/vczjk/sy7;->OooOOO:Llyiahf/vczjk/xr1;

    invoke-static {v2, v3, v3, v0, v1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
