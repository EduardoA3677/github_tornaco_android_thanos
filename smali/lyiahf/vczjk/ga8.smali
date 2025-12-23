.class public final Llyiahf/vczjk/ga8;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/ra8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ra8;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ga8;->this$0:Llyiahf/vczjk/ra8;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/xn4;

    iget-object v0, p0, Llyiahf/vczjk/ga8;->this$0:Llyiahf/vczjk/ra8;

    iget-object v0, v0, Llyiahf/vczjk/ra8;->OoooO0:Llyiahf/vczjk/um1;

    iput-object p1, v0, Llyiahf/vczjk/um1;->Oooo000:Llyiahf/vczjk/xn4;

    iget-boolean p1, v0, Llyiahf/vczjk/um1;->Oooo00o:Z

    if-eqz p1, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/um1;->o00000Oo()Llyiahf/vczjk/wj7;

    move-result-object p1

    if-eqz p1, :cond_0

    iget-wide v1, v0, Llyiahf/vczjk/um1;->Oooo0:J

    invoke-virtual {v0, p1, v1, v2}, Llyiahf/vczjk/um1;->o00000o0(Llyiahf/vczjk/wj7;J)Z

    move-result p1

    if-nez p1, :cond_0

    const/4 p1, 0x1

    iput-boolean p1, v0, Llyiahf/vczjk/um1;->Oooo00O:Z

    invoke-virtual {v0}, Llyiahf/vczjk/um1;->o0000Ooo()V

    :cond_0
    const/4 p1, 0x0

    iput-boolean p1, v0, Llyiahf/vczjk/um1;->Oooo00o:Z

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
