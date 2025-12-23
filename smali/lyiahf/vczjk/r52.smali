.class public final synthetic Llyiahf/vczjk/r52;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/v52;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/v52;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/r52;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/r52;->OooOOO:Llyiahf/vczjk/v52;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/r52;->OooOOO:Llyiahf/vczjk/v52;

    iget v1, p0, Llyiahf/vczjk/r52;->OooOOO0:I

    packed-switch v1, :pswitch_data_0

    sget-object v1, Llyiahf/vczjk/zt7;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-static {v0, v1}, Llyiahf/vczjk/t51;->OooOo(Llyiahf/vczjk/ug1;Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ut7;

    sget-object v0, Llyiahf/vczjk/so8;->OooO0OO:Llyiahf/vczjk/st7;

    return-object v0

    :pswitch_0
    sget-object v1, Llyiahf/vczjk/zt7;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-static {v0, v1}, Llyiahf/vczjk/t51;->OooOo(Llyiahf/vczjk/ug1;Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ut7;

    if-nez v1, :cond_1

    iget-object v1, v0, Llyiahf/vczjk/v52;->Oooo00O:Llyiahf/vczjk/tf;

    if-eqz v1, :cond_0

    invoke-virtual {v0, v1}, Llyiahf/vczjk/m52;->o00000Oo(Llyiahf/vczjk/l52;)V

    :cond_0
    const/4 v1, 0x0

    iput-object v1, v0, Llyiahf/vczjk/v52;->Oooo00O:Llyiahf/vczjk/tf;

    goto :goto_0

    :cond_1
    iget-object v1, v0, Llyiahf/vczjk/v52;->Oooo00O:Llyiahf/vczjk/tf;

    if-nez v1, :cond_2

    new-instance v6, Llyiahf/vczjk/s52;

    const/4 v1, 0x0

    invoke-direct {v6, v0, v1}, Llyiahf/vczjk/s52;-><init>(Ljava/lang/Object;I)V

    new-instance v7, Llyiahf/vczjk/r52;

    const/4 v1, 0x1

    invoke-direct {v7, v0, v1}, Llyiahf/vczjk/r52;-><init>(Llyiahf/vczjk/v52;I)V

    sget-object v1, Llyiahf/vczjk/yt7;->OooO00o:Llyiahf/vczjk/h1a;

    new-instance v2, Llyiahf/vczjk/tf;

    iget-object v3, v0, Llyiahf/vczjk/v52;->OooOoo:Llyiahf/vczjk/n24;

    iget-boolean v4, v0, Llyiahf/vczjk/v52;->OooOooO:Z

    iget v5, v0, Llyiahf/vczjk/v52;->OooOooo:F

    invoke-direct/range {v2 .. v7}, Llyiahf/vczjk/cu7;-><init>(Llyiahf/vczjk/n24;ZFLlyiahf/vczjk/w21;Llyiahf/vczjk/le3;)V

    invoke-virtual {v0, v2}, Llyiahf/vczjk/m52;->o00000OO(Llyiahf/vczjk/l52;)Llyiahf/vczjk/l52;

    iput-object v2, v0, Llyiahf/vczjk/v52;->Oooo00O:Llyiahf/vczjk/tf;

    :cond_2
    :goto_0
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
