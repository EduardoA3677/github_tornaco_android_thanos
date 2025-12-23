.class public final Llyiahf/vczjk/rm1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $animationState:Llyiahf/vczjk/oaa;

.field final synthetic $bringIntoViewSpec:Llyiahf/vczjk/gi0;

.field final synthetic this$0:Llyiahf/vczjk/um1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/um1;Llyiahf/vczjk/oaa;Llyiahf/vczjk/gi0;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/rm1;->this$0:Llyiahf/vczjk/um1;

    iput-object p2, p0, Llyiahf/vczjk/rm1;->$animationState:Llyiahf/vczjk/oaa;

    iput-object p3, p0, Llyiahf/vczjk/rm1;->$bringIntoViewSpec:Llyiahf/vczjk/gi0;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/rm1;->this$0:Llyiahf/vczjk/um1;

    iget-object v1, v0, Llyiahf/vczjk/um1;->OooOooo:Llyiahf/vczjk/sh0;

    :goto_0
    iget-object v2, v1, Llyiahf/vczjk/sh0;->OooO00o:Llyiahf/vczjk/ws5;

    iget v3, v2, Llyiahf/vczjk/ws5;->OooOOOO:I

    sget-object v4, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v5, 0x1

    if-eqz v3, :cond_2

    if-eqz v3, :cond_1

    add-int/lit8 v3, v3, -0x1

    iget-object v2, v2, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    aget-object v2, v2, v3

    check-cast v2, Llyiahf/vczjk/pm1;

    iget-object v2, v2, Llyiahf/vczjk/pm1;->OooO00o:Llyiahf/vczjk/yh0;

    invoke-virtual {v2}, Llyiahf/vczjk/yh0;->OooO00o()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/wj7;

    if-nez v2, :cond_0

    move v2, v5

    goto :goto_1

    :cond_0
    iget-wide v6, v0, Llyiahf/vczjk/um1;->Oooo0:J

    invoke-virtual {v0, v2, v6, v7}, Llyiahf/vczjk/um1;->o00000o0(Llyiahf/vczjk/wj7;J)Z

    move-result v2

    :goto_1
    if-eqz v2, :cond_2

    iget-object v2, v1, Llyiahf/vczjk/sh0;->OooO00o:Llyiahf/vczjk/ws5;

    iget v3, v2, Llyiahf/vczjk/ws5;->OooOOOO:I

    sub-int/2addr v3, v5

    invoke-virtual {v2, v3}, Llyiahf/vczjk/ws5;->OooOO0O(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/pm1;

    iget-object v2, v2, Llyiahf/vczjk/pm1;->OooO0O0:Llyiahf/vczjk/yp0;

    invoke-virtual {v2, v4}, Llyiahf/vczjk/yp0;->resumeWith(Ljava/lang/Object;)V

    goto :goto_0

    :cond_1
    new-instance v0, Ljava/util/NoSuchElementException;

    const-string v1, "MutableVector is empty."

    invoke-direct {v0, v1}, Ljava/util/NoSuchElementException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/rm1;->this$0:Llyiahf/vczjk/um1;

    iget-boolean v1, v0, Llyiahf/vczjk/um1;->Oooo00O:Z

    if-eqz v1, :cond_4

    invoke-virtual {v0}, Llyiahf/vczjk/um1;->o00000Oo()Llyiahf/vczjk/wj7;

    move-result-object v0

    const/4 v1, 0x0

    if-eqz v0, :cond_3

    iget-object v2, p0, Llyiahf/vczjk/rm1;->this$0:Llyiahf/vczjk/um1;

    iget-wide v6, v2, Llyiahf/vczjk/um1;->Oooo0:J

    invoke-virtual {v2, v0, v6, v7}, Llyiahf/vczjk/um1;->o00000o0(Llyiahf/vczjk/wj7;J)Z

    move-result v0

    if-ne v0, v5, :cond_3

    goto :goto_2

    :cond_3
    move v5, v1

    :goto_2
    if-eqz v5, :cond_4

    iget-object v0, p0, Llyiahf/vczjk/rm1;->this$0:Llyiahf/vczjk/um1;

    iput-boolean v1, v0, Llyiahf/vczjk/um1;->Oooo00O:Z

    :cond_4
    iget-object v0, p0, Llyiahf/vczjk/rm1;->$animationState:Llyiahf/vczjk/oaa;

    iget-object v1, p0, Llyiahf/vczjk/rm1;->this$0:Llyiahf/vczjk/um1;

    iget-object v2, p0, Llyiahf/vczjk/rm1;->$bringIntoViewSpec:Llyiahf/vczjk/gi0;

    invoke-static {v1, v2}, Llyiahf/vczjk/um1;->o00000OO(Llyiahf/vczjk/um1;Llyiahf/vczjk/gi0;)F

    move-result v1

    iput v1, v0, Llyiahf/vczjk/oaa;->OooO0o0:F

    return-object v4
.end method
