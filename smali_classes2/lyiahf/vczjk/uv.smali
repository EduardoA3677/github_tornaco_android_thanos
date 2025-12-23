.class public final synthetic Llyiahf/vczjk/uv;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/nl1;
.implements Llyiahf/vczjk/o0oo0000;


# instance fields
.field public final synthetic OooOOO0:Llyiahf/vczjk/bw;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/bw;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/uv;->OooOOO0:Llyiahf/vczjk/bw;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public accept(Ljava/lang/Object;)V
    .locals 0

    check-cast p1, Llyiahf/vczjk/nc2;

    iget-object p1, p0, Llyiahf/vczjk/uv;->OooOOO0:Llyiahf/vczjk/bw;

    iget-object p1, p1, Llyiahf/vczjk/bw;->OooO0o0:Landroidx/databinding/ObservableArrayList;

    invoke-virtual {p1}, Landroidx/databinding/ObservableArrayList;->clear()V

    return-void
.end method

.method public run()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/uv;->OooOOO0:Llyiahf/vczjk/bw;

    iget-object v0, v0, Llyiahf/vczjk/bw;->OooO0OO:Landroidx/databinding/ObservableBoolean;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Landroidx/databinding/ObservableBoolean;->set(Z)V

    return-void
.end method
