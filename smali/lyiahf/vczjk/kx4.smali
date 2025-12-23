.class public final Llyiahf/vczjk/kx4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/lx4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lx4;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/kx4;->this$0:Llyiahf/vczjk/lx4;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/gl9;

    iget-object v0, p1, Llyiahf/vczjk/gl9;->OooO00o:Llyiahf/vczjk/an;

    iget-object v0, v0, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    iget-object v1, p0, Llyiahf/vczjk/kx4;->this$0:Llyiahf/vczjk/lx4;

    iget-object v1, v1, Llyiahf/vczjk/lx4;->OooOO0:Llyiahf/vczjk/an;

    if-eqz v1, :cond_0

    iget-object v1, v1, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    :goto_0
    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/kx4;->this$0:Llyiahf/vczjk/lx4;

    sget-object v1, Llyiahf/vczjk/vl3;->OooOOO0:Llyiahf/vczjk/vl3;

    iget-object v0, v0, Llyiahf/vczjk/lx4;->OooOO0O:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget-object v0, p0, Llyiahf/vczjk/kx4;->this$0:Llyiahf/vczjk/lx4;

    iget-object v0, v0, Llyiahf/vczjk/lx4;->OooOo00:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/kx4;->this$0:Llyiahf/vczjk/lx4;

    iget-object v0, v0, Llyiahf/vczjk/lx4;->OooOo00:Llyiahf/vczjk/qs5;

    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    goto :goto_1

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/kx4;->this$0:Llyiahf/vczjk/lx4;

    iget-object v0, v0, Llyiahf/vczjk/lx4;->OooOOoo:Llyiahf/vczjk/qs5;

    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    :cond_2
    :goto_1
    iget-object v0, p0, Llyiahf/vczjk/kx4;->this$0:Llyiahf/vczjk/lx4;

    sget-wide v1, Llyiahf/vczjk/gn9;->OooO0O0:J

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/lx4;->OooO0o(J)V

    iget-object v0, p0, Llyiahf/vczjk/kx4;->this$0:Llyiahf/vczjk/lx4;

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/lx4;->OooO0o0(J)V

    iget-object v0, p0, Llyiahf/vczjk/kx4;->this$0:Llyiahf/vczjk/lx4;

    iget-object v0, v0, Llyiahf/vczjk/lx4;->OooOo0:Llyiahf/vczjk/oe3;

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    iget-object p1, p0, Llyiahf/vczjk/kx4;->this$0:Llyiahf/vczjk/lx4;

    iget-object p1, p1, Llyiahf/vczjk/lx4;->OooO0O0:Llyiahf/vczjk/aj7;

    invoke-virtual {p1}, Llyiahf/vczjk/aj7;->OooO0OO()V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
