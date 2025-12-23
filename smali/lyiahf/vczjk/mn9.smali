.class public final Llyiahf/vczjk/mn9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/qn9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/qn9;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/mn9;->this$0:Llyiahf/vczjk/qn9;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    check-cast p1, Llyiahf/vczjk/an;

    iget-object v0, p0, Llyiahf/vczjk/mn9;->this$0:Llyiahf/vczjk/qn9;

    iget-object v2, p1, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    iget-object p1, v0, Llyiahf/vczjk/qn9;->Oooo0o0:Llyiahf/vczjk/kn9;

    if-eqz p1, :cond_1

    iget-object v1, p1, Llyiahf/vczjk/kn9;->OooO0O0:Ljava/lang/String;

    invoke-static {v2, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    goto :goto_0

    :cond_0
    iput-object v2, p1, Llyiahf/vczjk/kn9;->OooO0O0:Ljava/lang/String;

    iget-object p1, p1, Llyiahf/vczjk/kn9;->OooO0Oo:Llyiahf/vczjk/fo6;

    if-eqz p1, :cond_2

    iget-object v1, v0, Llyiahf/vczjk/qn9;->OooOoo0:Llyiahf/vczjk/rn9;

    iget-object v3, v0, Llyiahf/vczjk/qn9;->OooOoo:Llyiahf/vczjk/aa3;

    iget v4, v0, Llyiahf/vczjk/qn9;->OooOooO:I

    iget-boolean v5, v0, Llyiahf/vczjk/qn9;->OooOooo:Z

    iget v6, v0, Llyiahf/vczjk/qn9;->Oooo000:I

    iget v0, v0, Llyiahf/vczjk/qn9;->Oooo00O:I

    iput-object v2, p1, Llyiahf/vczjk/fo6;->OooO00o:Ljava/lang/String;

    iput-object v1, p1, Llyiahf/vczjk/fo6;->OooO0O0:Llyiahf/vczjk/rn9;

    iput-object v3, p1, Llyiahf/vczjk/fo6;->OooO0OO:Llyiahf/vczjk/aa3;

    iput v4, p1, Llyiahf/vczjk/fo6;->OooO0Oo:I

    iput-boolean v5, p1, Llyiahf/vczjk/fo6;->OooO0o0:Z

    iput v6, p1, Llyiahf/vczjk/fo6;->OooO0o:I

    iput v0, p1, Llyiahf/vczjk/fo6;->OooO0oO:I

    invoke-virtual {p1}, Llyiahf/vczjk/fo6;->OooO0O0()V

    goto :goto_0

    :cond_1
    new-instance p1, Llyiahf/vczjk/kn9;

    iget-object v1, v0, Llyiahf/vczjk/qn9;->OooOoOO:Ljava/lang/String;

    invoke-direct {p1, v1, v2}, Llyiahf/vczjk/kn9;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    new-instance v1, Llyiahf/vczjk/fo6;

    iget-object v3, v0, Llyiahf/vczjk/qn9;->OooOoo0:Llyiahf/vczjk/rn9;

    iget-object v4, v0, Llyiahf/vczjk/qn9;->OooOoo:Llyiahf/vczjk/aa3;

    iget v5, v0, Llyiahf/vczjk/qn9;->OooOooO:I

    iget-boolean v6, v0, Llyiahf/vczjk/qn9;->OooOooo:Z

    iget v7, v0, Llyiahf/vczjk/qn9;->Oooo000:I

    iget v8, v0, Llyiahf/vczjk/qn9;->Oooo00O:I

    invoke-direct/range {v1 .. v8}, Llyiahf/vczjk/fo6;-><init>(Ljava/lang/String;Llyiahf/vczjk/rn9;Llyiahf/vczjk/aa3;IZII)V

    invoke-virtual {v0}, Llyiahf/vczjk/qn9;->o00000OO()Llyiahf/vczjk/fo6;

    move-result-object v2

    iget-object v2, v2, Llyiahf/vczjk/fo6;->OooO:Llyiahf/vczjk/o34;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/fo6;->OooO0OO(Llyiahf/vczjk/o34;)V

    iput-object v1, p1, Llyiahf/vczjk/kn9;->OooO0Oo:Llyiahf/vczjk/fo6;

    iput-object p1, v0, Llyiahf/vczjk/qn9;->Oooo0o0:Llyiahf/vczjk/kn9;

    :cond_2
    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/mn9;->this$0:Llyiahf/vczjk/qn9;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p1}, Llyiahf/vczjk/ll6;->OooO(Llyiahf/vczjk/ne8;)V

    invoke-static {p1}, Llyiahf/vczjk/t51;->Oooo00o(Llyiahf/vczjk/go4;)V

    invoke-static {p1}, Llyiahf/vczjk/ye5;->OooOoO0(Llyiahf/vczjk/fg2;)V

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1
.end method
