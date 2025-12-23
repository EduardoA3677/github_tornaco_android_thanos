.class public final synthetic Llyiahf/vczjk/vv;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/nl1;


# instance fields
.field public final synthetic OooOOO:Landroidx/databinding/ObservableArrayList;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Landroidx/databinding/ObservableArrayList;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/vv;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/vv;->OooOOO:Landroidx/databinding/ObservableArrayList;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final accept(Ljava/lang/Object;)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/vv;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/vv;->OooOOO:Landroidx/databinding/ObservableArrayList;

    check-cast p1, Llyiahf/vczjk/f1;

    invoke-virtual {v0, p1}, Landroidx/databinding/ObservableArrayList;->add(Ljava/lang/Object;)Z

    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/vv;->OooOOO:Landroidx/databinding/ObservableArrayList;

    check-cast p1, Llyiahf/vczjk/y19;

    invoke-virtual {v0, p1}, Landroidx/databinding/ObservableArrayList;->add(Ljava/lang/Object;)Z

    return-void

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/vv;->OooOOO:Landroidx/databinding/ObservableArrayList;

    check-cast p1, Llyiahf/vczjk/y09;

    invoke-virtual {v0, p1}, Landroidx/databinding/ObservableArrayList;->add(Ljava/lang/Object;)Z

    return-void

    :pswitch_2
    iget-object v0, p0, Llyiahf/vczjk/vv;->OooOOO:Landroidx/databinding/ObservableArrayList;

    check-cast p1, Lgithub/tornaco/android/thanos/core/profile/GlobalVar;

    invoke-virtual {v0, p1}, Landroidx/databinding/ObservableArrayList;->add(Ljava/lang/Object;)Z

    return-void

    :pswitch_3
    iget-object v0, p0, Llyiahf/vczjk/vv;->OooOOO:Landroidx/databinding/ObservableArrayList;

    check-cast p1, Llyiahf/vczjk/wu;

    invoke-virtual {v0, p1}, Landroidx/databinding/ObservableArrayList;->add(Ljava/lang/Object;)Z

    return-void

    :pswitch_4
    iget-object v0, p0, Llyiahf/vczjk/vv;->OooOOO:Landroidx/databinding/ObservableArrayList;

    check-cast p1, Llyiahf/vczjk/oc6;

    invoke-virtual {v0, p1}, Landroidx/databinding/ObservableArrayList;->add(Ljava/lang/Object;)Z

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
