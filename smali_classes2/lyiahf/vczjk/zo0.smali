.class public final Llyiahf/vczjk/zo0;
.super Llyiahf/vczjk/cp0;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/rg0;


# instance fields
.field public final OooO0o:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ljava/lang/reflect/Field;ZLjava/lang/Object;)V
    .locals 1

    const-string v0, "field"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    invoke-direct {p0, p1, p2, v0}, Llyiahf/vczjk/cp0;-><init>(Ljava/lang/reflect/Field;ZZ)V

    iput-object p3, p0, Llyiahf/vczjk/zo0;->OooO0o:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooO0Oo([Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    const-string v0, "args"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0, p1}, Llyiahf/vczjk/cp0;->OooO0o0([Ljava/lang/Object;)V

    iget-object v0, p0, Llyiahf/vczjk/jp0;->OooO00o:Ljava/lang/reflect/Member;

    check-cast v0, Ljava/lang/reflect/Field;

    iget-object v1, p0, Llyiahf/vczjk/zo0;->OooO0o:Ljava/lang/Object;

    invoke-static {p1}, Llyiahf/vczjk/sy;->oo0o0Oo([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {v0, v1, p1}, Ljava/lang/reflect/Field;->set(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
